<?php
namespace CERCHECW\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;

require_once __DIR__ . '/UnsafeCrypto.php';
require_once __DIR__ . '/SaferCrypto.php';

/**
 * REDCap Field Encryption Module
 *
 * Encrypts sensitive field data marked with @ENCRYPT action tag.
 * Encrypted values are stored with an "ENC:" prefix and automatically
 * decrypted when sending automated emails.
 */
class FieldEncryptionModule extends AbstractExternalModule
{
    // Prevents infinite loops when hooks trigger each other
    private static $processingRecord = [];

    /**
     * Look up which data table this project uses.
     * Some REDCap installations use custom tables like redcap_data2.
     */
    private function getDataTable($project_id)
    {
        $result = $this->query("SELECT data_table FROM redcap_projects WHERE project_id = ?", [$project_id]);

        if ($result && $row = $result->fetch_assoc()) {
            $tableName = $row['data_table'] ?? 'redcap_data';
            $this->log("Found data table for project", [
                'project_id' => $project_id,
                'table_name' => $tableName
            ]);
            return $tableName;
        }

        $this->log("Could not find data table, using default", [
            'project_id' => $project_id
        ]);
        return 'redcap_data';
    }

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

    // ========================================
    // Encryption/Decryption Methods
    // ========================================

    /**
     * Encrypt a plaintext value and add the ENC: prefix
     */
    public function encryptValue($plaintext)
    {
        $key = $this->getEncryptionKey();
        $encrypted = SaferCrypto::encrypt($plaintext, $key, true);
        return 'ENC:' . $encrypted;
    }

    /**
     * Decrypt a value if it has the ENC: prefix, otherwise return as-is
     */
    public function decryptValue($encryptedValue)
    {
        if (strpos($encryptedValue, 'ENC:') !== 0) {
            return $encryptedValue;
        }

        $key = $this->getEncryptionKey();
        $encrypted = substr($encryptedValue, 4);
        return SaferCrypto::decrypt($encrypted, $key, true);
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
                    'is_encrypted' => strpos($value, 'ENC:') === 0
                ]);

                // Skip empty values or already encrypted data
                if (empty($value) || strpos($value, 'ENC:') === 0) {
                    $this->log("Skipping field - empty or already encrypted", [
                        'field' => $fieldName
                    ]);
                    continue;
                }

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

            // Write encrypted values directly to the database
            // We bypass REDCap::saveData() because it re-validates field formats
            if (!empty($updatedData)) {
                $this->saveEncryptedData($project_id, $event_id, $record, $repeat_instance, $updatedData);
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
     * Write encrypted values directly to database to bypass field validation
     */
    private function saveEncryptedData($project_id, $event_id, $record, $repeat_instance, $updatedData)
    {
        $dataTable = $this->getDataTable($project_id);

        $this->log("Saving encrypted data to database", [
            'table' => $dataTable,
            'record' => $record,
            'event_id' => $event_id,
            'repeat_instance' => $repeat_instance,
            'fields' => json_encode(array_keys($updatedData))
        ]);

        foreach ($updatedData as $fieldName => $encryptedValue) {
            if ($repeat_instance > 1) {
                $sql = "UPDATE $dataTable
                        SET value = ?
                        WHERE project_id = ?
                          AND event_id = ?
                          AND record = ?
                          AND field_name = ?
                          AND instance = ?";
                $params = [$encryptedValue, $project_id, $event_id, $record, $fieldName, $repeat_instance];
            } else {
                $sql = "UPDATE $dataTable
                        SET value = ?
                        WHERE project_id = ?
                          AND event_id = ?
                          AND record = ?
                          AND field_name = ?
                          AND (instance IS NULL OR instance = 1)";
                $params = [$encryptedValue, $project_id, $event_id, $record, $fieldName];
            }

            $this->log("Executing SQL UPDATE", [
                'table' => $dataTable,
                'sql' => $sql,
                'params' => json_encode($params),
                'field' => $fieldName
            ]);

            $result = $this->query($sql, $params);

            $this->log("SQL UPDATE result", [
                'field' => $fieldName,
                'affected_rows' => $result->affected_rows
            ]);

            if ($result->affected_rows === 0) {
                $this->log("WARNING: No rows updated", [
                    'table' => $dataTable,
                    'project_id' => $project_id,
                    'event_id' => $event_id,
                    'record' => $record,
                    'field_name' => $fieldName
                ]);
            }
        }

        // Log to REDCap's audit trail
        \REDCap::logEvent(
            "Field Encryption Module",
            "Encrypted fields: " . implode(', ', array_keys($updatedData)),
            null,
            $record,
            null,
            $project_id
        );

        $this->log("Database save complete");
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
        $(document).ready(function() {
            var fieldsToMask = " . json_encode($fieldsToEncrypt) . ";

            fieldsToMask.forEach(function(fieldName) {
                // Try multiple selectors to catch all field types
                var field = $('input[name=\"' + fieldName + '\"], textarea[name=\"' + fieldName + '\"], select[name=\"' + fieldName + '\"]');

                if (field.length > 0) {
                    var currentValue = field.val();

                    if (currentValue && currentValue.toString().indexOf('ENC:') === 0) {
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
                if (isset($record[$fieldName]) && !empty($record[$fieldName]) && strpos($record[$fieldName], 'ENC:') === 0) {
                    $record[$fieldName] = '[ENCRYPTED]';
                }
            }
        }

        return $data;
    }

    // ========================================
    // Email Decryption Hook
    // ========================================

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

            if (!empty($to) && strpos($to, 'ENC:') === 0) {
                $decryptedTo = $this->decryptValue($to);
                $modified = true;
                $this->log("Decrypted TO email address", [
                    'original_length' => strlen($to),
                    'decrypted_email' => $decryptedTo
                ]);
            }

            if (!empty($cc) && strpos($cc, 'ENC:') === 0) {
                $decryptedCc = $this->decryptValue($cc);
                $modified = true;
                $this->log("Decrypted CC email address");
            }

            if (!empty($bcc) && strpos($bcc, 'ENC:') === 0) {
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
}
