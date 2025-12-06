<?php
namespace CERCHECW\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;

require_once __DIR__ . '/UnsafeCrypto.php';
require_once __DIR__ . '/SaferCrypto.php';

/**
 * REDCap Field Encryption Module
 *
 * Encrypts sensitive field data marked with @ENCRYPT action tag.
 * Encrypted values are stored in a format that passes REDCap's email validation
 * (ENC_[url-safe-base64]@xx.xx) and automatically decrypted when sending emails.
 */
class FieldEncryptionModule extends AbstractExternalModule
{
    // Prevents infinite loops when hooks trigger each other
    private static $processingRecord = [];

    /**
     * Retrieve the encryption key from system settings
     */
    private function getEncryptionKey()
    {
        $keyHex = $this->getSystemSetting('encryption-key');

        if (empty($keyHex)) {
            throw new \Exception('Encryption key not set in system settings');
        }

        return hex2bin($keyHex);
    }

    /**
     * Find all fields in the data dictionary with @ENCRYPT action tag
     */
    private function getFieldsToEncrypt($project_id = null)
    {
        if ($project_id === null) {
            $project_id = $this->getProjectId();
        }

        $this->log("Getting fields to encrypt", ['project_id' => $project_id]);

        $dictionary = \REDCap::getDataDictionary($project_id, 'array');

        if (empty($dictionary)) {
            $this->log("WARNING: Data dictionary is empty", ['project_id' => $project_id]);
            return [];
        }

        $fieldsToEncrypt = [];

        foreach ($dictionary as $fieldName => $fieldInfo) {
            $actionTags = $fieldInfo['field_annotation'] ?? '';

            if (stripos($actionTags, '@ENCRYPT') !== false) {
                $fieldsToEncrypt[] = $fieldName;
                $this->log("Found field with @ENCRYPT tag", [
                    'field' => $fieldName,
                    'annotation' => $actionTags
                ]);
            }
        }

        $this->log("Fields to encrypt", [
            'fields' => json_encode($fieldsToEncrypt),
            'count' => count($fieldsToEncrypt)
        ]);

        return $fieldsToEncrypt;
    }

    // Encryption/Decryption Methods

    /**
     * Encrypt a plaintext value using URL-safe base64 and format as fake email
     * Format: ENC_[url-safe-base64]@xx.xx
     * This passes REDCap's email validation while keeping data encrypted
     */
    public function encryptValue($plaintext)
    {
        $key = $this->getEncryptionKey();
        $encrypted = SaferCrypto::encrypt($plaintext, $key, true);

        // Convert to URL-safe base64: replace +/ with -_ and remove =
        $urlSafe = rtrim(strtr($encrypted, '+/', '-_'), '=');

        // Format as fake email that passes validation
        return 'ENC_' . $urlSafe . '@xx.xx';
    }

    /**
     * Decrypt a value if it has the encrypted email format, otherwise return as-is
     * Handles format: ENC_[url-safe-base64]@xx.xx
     */
    public function decryptValue($encryptedValue)
    {
        // Check if this is our encrypted format
        if (strpos($encryptedValue, '@xx.xx') === false) {
            return $encryptedValue;
        }

        // Extract the part before @xx.xx
        $localPart = substr($encryptedValue, 0, strpos($encryptedValue, '@'));

        // Check if it starts with ENC_
        if (strpos($localPart, 'ENC_') !== 0) {
            return $encryptedValue;
        }

        // Remove "ENC_" prefix
        $urlSafeBase64 = substr($localPart, 4);

        // Convert back from URL-safe base64: replace -_ with +/
        $base64 = strtr($urlSafeBase64, '-_', '+/');

        // Restore padding
        $remainder = strlen($base64) % 4;
        if ($remainder) {
            $base64 .= str_repeat('=', 4 - $remainder);
        }

        $key = $this->getEncryptionKey();
        return SaferCrypto::decrypt($base64, $key, true);
    }

    // Data Encryption Hooks
    /**
     * Triggered when a record is saved (data entry forms)
     */
    public function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Triggered when a survey is completed
     */
    public function redcap_survey_complete($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance);
    }

    /**
     * Main encryption logic - reads record data and encrypts marked fields
     */
    private function encryptRecordData($project_id, $record, $instrument, $event_id, $repeat_instance)
    {
        try {
            $repeat_instance = $repeat_instance ?: 1;
            $recordKey = "$project_id:$record:$event_id:$repeat_instance";

            // Prevent infinite loops if hooks trigger each other
            if (isset(self::$processingRecord[$recordKey])) {
                $this->log("Skipping - already processing this record", [
                    'recordKey' => $recordKey
                ]);
                return;
            }

            self::$processingRecord[$recordKey] = true;

            $this->log("Starting encryption process", [
                'project_id' => $project_id,
                'record' => $record,
                'instrument' => $instrument,
                'event_id' => $event_id,
                'repeat_instance' => $repeat_instance
            ]);

            // Find which fields need encryption
            $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);

            if (empty($fieldsToEncrypt)) {
                $this->log("No fields to encrypt - exiting");
                return;
            }

            // Fetch the current record data
            $params = [
                'project_id' => $project_id,
                'return_format' => 'array',
                'records' => [$record],
                'events' => [$event_id]
            ];

            if ($repeat_instance > 1) {
                $params['redcap_repeat_instance'] = $repeat_instance;
            }

            $this->log("Fetching record data", [
                'params' => json_encode($params)
            ]);

            $data = \REDCap::getData($params);

            if (empty($data) || !isset($data[$record][$event_id])) {
                $this->log("ERROR: getData returned empty or missing data structure", [
                    'has_data' => !empty($data),
                    'has_record' => isset($data[$record]),
                    'has_event' => isset($data[$record][$event_id])
                ]);
                return;
            }

            $this->log("Successfully fetched record data");

            $recordData = $data[$record][$event_id];

            // Handle repeating instruments
            if ($repeat_instance > 1 && isset($recordData['repeat_instances'][$instrument][$repeat_instance])) {
                $recordData = $recordData['repeat_instances'][$instrument][$repeat_instance];
                $this->log("Using repeating instrument data", [
                    'instrument' => $instrument,
                    'instance' => $repeat_instance
                ]);
            }

            $this->log("Record data available", [
                'fields' => json_encode(array_keys($recordData))
            ]);

            // Check each field and encrypt if needed
            $updatedData = [];
            $plaintextEmails = []; // Store original email values for participant table

            foreach ($fieldsToEncrypt as $fieldName) {
                $this->log("Checking field", ['field' => $fieldName]);

                if (!isset($recordData[$fieldName])) {
                    $this->log("Field not in record data", ['field' => $fieldName]);
                    continue;
                }

                $value = $recordData[$fieldName];

                $this->log("Field value", [
                    'field' => $fieldName,
                    'value' => $value,
                    'is_empty' => empty($value),
                    'is_encrypted' => (strpos($value, 'ENC_') === 0 && strpos($value, '@xx.xx') !== false)
                ]);

                // Skip empty values or already encrypted data
                if (empty($value) || (strpos($value, 'ENC_') === 0 && strpos($value, '@xx.xx') !== false)) {
                    $this->log("Skipping field - empty or already encrypted", [
                        'field' => $fieldName
                    ]);
                    continue;
                }

                // Store original email value before encryption
                $plaintextEmails[$fieldName] = $value;

                $this->log("Encrypting field", ['field' => $fieldName]);
                $encryptedValue = $this->encryptValue($value);
                $this->log("Field encrypted successfully", [
                    'field' => $fieldName,
                    'encrypted_preview' => substr($encryptedValue, 0, 20) . '...'
                ]);

                $updatedData[$fieldName] = $encryptedValue;
            }

            $this->log("Encryption processing complete", [
                'fields_encrypted' => json_encode(array_keys($updatedData)),
                'count' => count($updatedData)
            ]);

            // Save encrypted values using REDCap's standard method
            // Now that we use URL-safe format with @xx.xx, this passes validation
            if (!empty($updatedData)) {
                // Prepare data for REDCap::saveData
                $saveData = [
                    $record => [
                        $event_id => $updatedData
                    ]
                ];

                $this->log("Saving encrypted data via REDCap::saveData", [
                    'record' => $record,
                    'event_id' => $event_id,
                    'fields' => json_encode(array_keys($updatedData))
                ]);

                $result = \REDCap::saveData($project_id, 'array', $saveData, 'overwrite');

                if (!empty($result['errors'])) {
                    $this->log("Error saving encrypted data", [
                        'errors' => json_encode($result['errors'])
                    ]);
                } else {
                    $this->log("Successfully saved encrypted data", [
                        'item_count' => $result['item_count']
                    ]);

                    // Log to REDCap's audit trail
                    \REDCap::logEvent(
                        "Field Encryption Module",
                        "Encrypted fields: " . implode(', ', array_keys($updatedData)),
                        null,
                        $record,
                        null,
                        $project_id
                    );

                    // Update participant table with encrypted email for ASI to work
                    $this->updateParticipantEmail($project_id, $record, $event_id, $updatedData);
                }
            } else {
                $this->log("No fields need updating");
            }

        } catch (\Exception $e) {
            $this->log("CRITICAL ERROR in encryption process", [
                'error' => $e->getMessage(),
                'record' => $record,
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ]);
        } finally {
            if (isset($recordKey)) {
                unset(self::$processingRecord[$recordKey]);
                $this->log("Cleared processing flag", ['recordKey' => $recordKey]);
            }
        }
    }

    /**
     * Update participant email with encrypted value so ASI can send
     */
    private function updateParticipantEmail($project_id, $record, $event_id, $updatedData)
    {
        try {
            // Check if this project has a designated email field for participants
            $emailFieldQuery = "SELECT survey_email_participant_field FROM redcap_projects WHERE project_id = ?";
            $result = $this->query($emailFieldQuery, [$project_id]);

            if (!$result || !($row = $result->fetch_assoc())) {
                $this->log("No project settings found for participant email");
                return;
            }

            $emailFieldName = $row['survey_email_participant_field'];

            if (empty($emailFieldName)) {
                $this->log("No email field designated for participants");
                return;
            }

            // Check if we encrypted this field
            if (!isset($updatedData[$emailFieldName])) {
                $this->log("Email field not in encrypted data", [
                    'email_field' => $emailFieldName
                ]);
                return;
            }

            $encryptedEmail = $updatedData[$emailFieldName];

            $this->log("Updating participant email with encrypted value", [
                'email_field' => $emailFieldName,
                'encrypted_preview' => substr($encryptedEmail, 0, 30) . '...'
            ]);

            // Update ALL participant records for this record
            $updateSql = "UPDATE redcap_surveys_participants p
                         INNER JOIN redcap_surveys s ON p.survey_id = s.survey_id
                         INNER JOIN redcap_surveys_response r ON p.participant_id = r.participant_id
                         SET p.participant_email = ?
                         WHERE r.record = ?
                         AND p.event_id = ?
                         AND s.project_id = ?";

            $updateResult = $this->query($updateSql, [$encryptedEmail, $record, $event_id, $project_id]);

            $this->log("Participant email update result", [
                'affected_rows' => $updateResult ? $updateResult->affected_rows : 0,
                'record' => $record,
                'event_id' => $event_id
            ]);

        } catch (\Exception $e) {
            $this->log("Error updating participant email", [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }
    }

    // Display & Export Masking Hooks
    /**
     * Show a privacy notice on forms with encrypted fields
     */
    public function redcap_data_entry_form_top($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);

        if (!empty($fieldsToEncrypt)) {
            echo "<div style='background-color: #fff3cd; border: 1px solid #ffc107; padding: 10px; margin: 10px 0; border-radius: 4px;'>
                <strong>Privacy Notice:</strong> This form contains encrypted fields that are hidden for privacy protection.
            </div>";
        }
    }

    /**
     * Hide encrypted values in data entry forms
     */
    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        $this->maskEncryptedFields($project_id);
    }

    /**
     * Hide encrypted values on survey pages
     */
    public function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        $this->maskEncryptedFields($project_id);
    }

    /**
     * Inject JavaScript to mask encrypted field values in the UI
     */
    private function maskEncryptedFields($project_id)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);

        if (empty($fieldsToEncrypt)) {
            return;
        }

        echo "<script type='text/javascript'>
        (function() {
            $(document).ready(function() {
                var fieldsToMask = " . json_encode($fieldsToEncrypt, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ";

                fieldsToMask.forEach(function(fieldName) {
                    // Escape field name for use in jQuery selector
                    var escapedFieldName = fieldName.replace(/[!"#$%&'()*+,.\/:;<=>?@\[\\\]^`{|}~]/g, '\\\\$&');

                    // Try multiple selectors to catch all field types
                    var field = $('input[name=\"' + escapedFieldName + '\"], textarea[name=\"' + escapedFieldName + '\"], select[name=\"' + escapedFieldName + '\"]');

                    if (field.length > 0) {
                        var currentValue = field.val();

                        // Check for encrypted format: ENC_[base64]@xx.xx
                        if (currentValue && currentValue.toString().indexOf('ENC_') === 0 && currentValue.toString().indexOf('@xx.xx') !== -1) {
                            field.val('[ENCRYPTED]');
                            field.prop('readonly', true);
                            field.prop('disabled', false); // Keep enabled so form can submit
                            field.css({
                                'background-color': '#f0f0f0',
                                'color': '#666',
                                'font-style': 'italic',
                                'cursor': 'not-allowed'
                            });

                            // Prevent any changes to the field
                            field.on('focus', function() {
                                $(this).blur();
                            });
                        }
                    }
                });
            });
        })();
        </script>";
    }

    /**
     * Mask encrypted values in reports
     */
    public function redcap_report_data($project_id, $data, $fields, $events, $groups, $records)
    {
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);

        if (empty($fieldsToEncrypt)) {
            return $data;
        }

        foreach ($data as &$record) {
            foreach ($fieldsToEncrypt as $fieldName) {
                if (isset($record[$fieldName]) && !empty($record[$fieldName]) && strpos($record[$fieldName], 'ENC_') === 0 && strpos($record[$fieldName], '@xx.xx') !== false) {
                    $record[$fieldName] = '[ENCRYPTED]';
                }
            }
        }

        return $data;
    }
    // Email Decryption Hook

    /**
     * Automatically decrypt email addresses for survey invitations
     * REDCap stores encrypted emails, but we need real addresses to send invites
     */
    public function redcap_email($to, $from, $subject, $message, $cc, $bcc, $fromName, $attachments)
    {
        try {
            $modified = false;
            $decryptedTo = $to;
            $decryptedCc = $cc;
            $decryptedBcc = $bcc;

            // Check for encrypted email format: ENC_[base64]@xx.xx
            if (!empty($to) && strpos($to, 'ENC_') === 0 && strpos($to, '@xx.xx') !== false) {
                $decryptedTo = $this->decryptValue($to);
                $modified = true;
                $this->log("Decrypted TO email address", [
                    'encrypted_format' => substr($to, 0, 20) . '...',
                    'decrypted_email' => $decryptedTo
                ]);
            }

            if (!empty($cc) && strpos($cc, 'ENC_') === 0 && strpos($cc, '@xx.xx') !== false) {
                $decryptedCc = $this->decryptValue($cc);
                $modified = true;
                $this->log("Decrypted CC email address");
            }

            if (!empty($bcc) && strpos($bcc, 'ENC_') === 0 && strpos($bcc, '@xx.xx') !== false) {
                $decryptedBcc = $this->decryptValue($bcc);
                $modified = true;
                $this->log("Decrypted BCC email address");
            }

            // Send email with decrypted addresses and prevent REDCap from sending again
            if ($modified) {
                \REDCap::email($decryptedTo, $from, $subject, $message, $decryptedCc, $decryptedBcc, $fromName, $attachments);
                $this->log("Email sent with decrypted addresses", [
                    'to' => $decryptedTo,
                    'subject' => substr($subject, 0, 50)
                ]);
                return false;
            }

        } catch (\Exception $e) {
            $this->log("Email decryption failed", [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString()
            ]);
        }

        return true;
    }

    /**
     * Cron job to process scheduled survey invitations with encrypted emails
     */
    public function processScheduledSurveyInvitations()
    {
        try {
            $this->log("Cron: Starting processScheduledSurveyInvitations");

            // Find all scheduled invitations that are ready to send and have encrypted emails
            $sql = "SELECT ssq.ssq_id, ssq.record, ssq.scheduled_time_to_send, ssq.ss_id,
                           er.participant_id, p.participant_email, p.hash,
                           surv.survey_id, surv.project_id, surv.form_name, ss.event_id,
                           ss.email_subject, ss.email_content, ss.email_sender
                    FROM redcap_surveys_scheduler_queue ssq
                    INNER JOIN redcap_surveys_emails_recipients er ON ssq.email_recip_id = er.email_recip_id
                    INNER JOIN redcap_surveys_participants p ON er.participant_id = p.participant_id
                    INNER JOIN redcap_surveys_scheduler ss ON ssq.ss_id = ss.ss_id
                    INNER JOIN redcap_surveys surv ON ss.survey_id = surv.survey_id
                    WHERE ssq.scheduled_time_to_send <= NOW()
                    AND (ssq.status = 'QUEUED' OR (ssq.status = 'DID NOT SEND' AND ssq.reason_not_sent = 'EMAIL ATTEMPT FAILED'))
                    AND p.participant_email LIKE 'ENC_%@xx.xx'
                    ORDER BY ssq.scheduled_time_to_send ASC
                    LIMIT 200";

            $this->log("Cron: Executing query");

            try {
                $result = $this->query($sql, []); // Empty array required for prepared statements
                $this->log("Cron: Query call completed", [
                    'result_type' => gettype($result),
                    'is_object' => is_object($result)
                ]);
            } catch (\Exception $queryEx) {
                $this->log("Cron: Query threw exception", [
                    'error' => $queryEx->getMessage(),
                    'code' => $queryEx->getCode()
                ]);
                throw $queryEx;
            }

            if (!$result) {
                $this->log("Cron: Query returned false/null");
                return;
            }

            $this->log("Cron: Query executed successfully");

            $processedCount = 0;
            $failedCount = 0;

            // Check if result is valid
            if (!is_object($result) || !method_exists($result, 'fetch_assoc')) {
                $this->log("Cron: Invalid result object", [
                    'result_type' => gettype($result)
                ]);
                return;
            }

            while ($row = $result->fetch_assoc()) {
                try {
                    $this->log("Cron: Processing invitation", [
                        'ssq_id' => $row['ssq_id'],
                        'record' => $row['record'],
                        'encrypted_email_preview' => substr($row['participant_email'], 0, 30) . '...'
                    ]);

                    // Decrypt the email address
                    $decryptedEmail = $this->decryptValue($row['participant_email']);

                    if (!$decryptedEmail || $decryptedEmail === $row['participant_email']) {
                        throw new \Exception("Failed to decrypt email");
                    }

                    $this->log("Cron: Email decrypted successfully", [
                        'ssq_id' => $row['ssq_id'],
                        'decrypted_email' => $decryptedEmail
                    ]);

                    // Set project context for REDCap functions
                    $_GET['pid'] = $row['project_id'];
                    if (!defined('PROJECT_ID')) {
                        define('PROJECT_ID', $row['project_id']);
                    }

                    // Build survey link using the participant hash
                    $surveyLink = APP_PATH_SURVEY_FULL . "?s=" . $row['hash'];
                    $this->log("Cron: Generated survey link: " . $surveyLink);

                    // Prepare email content
                    $emailSubject = $row['email_subject'] ?: "Survey Invitation";
                    $emailContent = $row['email_content'] ?: "Please complete the survey: " . $surveyLink;
                    $emailSender = $row['email_sender'] ?: "noreply@" . $_SERVER['SERVER_NAME'];

                    // Replace survey link placeholders
                    $surveyLinkClickable = '<a href="' . $surveyLink . '">Survey Link</a>';
                    $emailContent = str_replace('[survey-link]', $surveyLinkClickable, $emailContent);
                    $emailContent = str_replace('[survey-url]', $surveyLink, $emailContent);

                    $this->log("Cron: Attempting to send email - Record: " . $row['record'] . ", Survey ID: " . $row['survey_id'] . ", Subject: " . substr($emailSubject, 0, 50));

                    // Use REDCap's Messaging class 
                    $emailSent = \REDCap::email($decryptedEmail, $emailSender, $emailSubject, $emailContent, '', '', '', [], $row['project_id']);

                    $this->log("Cron: REDCap::email() with project context returned: " . ($emailSent ? 'true' : 'false'));

                    if ($emailSent) {
                        // Mark as sent in the queue
                        $updateSql = "UPDATE redcap_surveys_scheduler_queue
                                      SET status = 'SENT',
                                          time_sent = NOW(),
                                          reason_not_sent = NULL
                                      WHERE ssq_id = ?";
                        $this->query($updateSql, [$row['ssq_id']]);

                        $this->log("Cron: Email sent successfully", [
                            'ssq_id' => $row['ssq_id'],
                            'record' => $row['record'],
                            'survey_id' => $row['survey_id']
                        ]);

                        $processedCount++;
                    } else {
                        throw new \Exception("REDCap::email() returned false");
                    }

                } catch (\Exception $e) {
                    $this->log("Cron: Failed ssq_id " . $row['ssq_id'] . " - " . $e->getMessage());
                    $this->log("Cron: Failure location - " . $e->getFile() . ":" . $e->getLine());

                    // Mark as failed
                    $updateSql = "UPDATE redcap_surveys_scheduler_queue
                                  SET status = 'DID NOT SEND',
                                      reason_not_sent = 'EMAIL ATTEMPT FAILED'
                                  WHERE ssq_id = ?";
                    $this->query($updateSql, [$row['ssq_id']]);

                    $failedCount++;
                }
            }

            $this->log("Cron: Finished processing invitations", [
                'processed' => $processedCount,
                'failed' => $failedCount
            ]);

        } catch (\Exception $e) {
            $this->log("Cron: Fatal error - " . $e->getMessage());
            $this->log("Cron: Error code - " . $e->getCode());
            $this->log("Cron: Error file - " . $e->getFile() . ":" . $e->getLine());
            $this->log("Cron: Stack trace - " . substr($e->getTraceAsString(), 0, 500));
        }
    }

}