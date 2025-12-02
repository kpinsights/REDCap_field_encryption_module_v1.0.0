<?php
namespace CERCHECW\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;
use CERCHECW\FieldEncryptionModule\SaferCrypto; 

/**
 * Field Encryption Module
 * Encrypts sensitive field values to protect participant privacy
 */

class FieldEncryptionModule extends AbstractExternalModule
{
    /** 
     * Get the encryption key from system settings
     * @return string (raw binary)
     * @throws \Exception if the key is not set
     */
    private function getEncryptionKey()
    {
        $keyHex = $this->getSystemSetting('encryption-key');
        
        if (empty($keyHex)) {
            throw new \Exception('Encryption key not configured in system settings');
        }
        myKey =  hex2bin($keyHex);
        print $myKey;
        return $myKey;
    }

    /**
     * Get list of fields with @ENCRYPT action tag in this project
     * 
     * @param int|null $project_id Optional project ID (uses current project if null)
     * @return array List of field names to encrypt
     */
    private function getFieldsToEncrypt($project_id = null)
    {
        if ($project_id === null) {
            $project_id = $this->getProjectId();
        }
        
        $fieldsToEncrypt = [];
        
        // Get data dictionary for this project
        $dictionary = \REDCap::getDataDictionary($project_id, 'array');
        
        // Look for @ENCRYPT tag in each field's annotations
        foreach ($dictionary as $fieldName => $fieldInfo) {
            $actionTags = $fieldInfo['field_annotation'] ?? '';
            
            // Check if @ENCRYPT tag is present
            if (stripos($actionTags, '@ENCRYPT') !== false) {
                $fieldsToEncrypt[] = $fieldName;
            }
        }
        
        return $fieldsToEncrypt;
    }
    /**
     * Encrypt a given plaintext value
     * 
     * @param string Value to encrypt
     * @return string Encrypted value
     */
    public function encryptValue($plaintext)
    {
        $key = $this->getEncryptionKey();
        $encrypted = SaferCrypto::encrypt($plaintext, $key, true);
        return 'ENC:' . $encrypted; // ENC: Prefix to identify encrypted values
    }
    /**
     * Decrypt a given encrypted value
     * 
     * @param string Encrypted value
     * @return string Decrypted plaintext value
     */
    public function decryptValue($encryptedValue)
    {
        //Check if the value is encrypted
        // If the position of ENC: is not at the start, return the value as is
        if(strpos($encryptedValue, 'ENC:') !== 0) {
            return $encryptedValue; // Not encrypted, return as is
        }

        $key = $this->getEncryptionKey();
        $encrypted = substr($encryptedValue, 4); // Remove ENC: prefix
        $decrypted = SaferCrypto::decrypt($encrypted, $key, true);
        return $decrypted;
    }

    /** 
     * Hook: redcap_save_record
     * Encrypt fields before saving to database
     */
    public function redcap_save_record($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        // Get fields to encrypt 
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        // If none, exit early
        if (empty($fieldsToEncrypt)) {
            return;
        }
        
        //Get current data record dqata
        $params = [
            'project_id' => $project_id,
            'return_format' => 'array',
            'records' => [$record],
            'events' => [$event_id]
        ];

        if ($repeat_instance > 1) {
            $params['redcap_repeat_instance'] = $repeat_instance;
        }
        $data = \REDCap::getData($params);

        // check if there is data to process
        if (empty($data) || !isset($data[$record][$event_id])) {
            return;
        }

        $recordData = $data[$record][$event_id];

        if ($repeat_instance > 1 && isset($recordData['repeat_instances'][$instrument][$repeat_instance])) {
            $recordData = $recordData['repeat_instances'][$instrument][$repeat_instance];
        }
        
        $needsUpdate = false;
        $updatedData = [];

        // Check each field that needs encryption
        foreach ($fieldsToEncrypt as $fieldName) {
            // Skip if field doesn't exist in current data
            if (!isset($recordData[$fieldName])) {
                continue;
            }
            
            $value = $recordData[$fieldName];
            
            // Skip if empty or already encrypted
            if (empty($value) || strpos($value, 'ENC:') === 0) {
                continue;
            }
            
            // Encrypt the value
            $encryptedValue = $this->encryptValue($value);
            $updatedData[$fieldName] = $encryptedValue;
            $needsUpdate = true;
        }
        
        // Save encrypted values back to database
        if ($needsUpdate) {
            $saveParams = [
                'project_id' => $project_id,
                'dataFormat' => 'array',
                'data' => [
                    $record => [
                        $event_id => $updatedData
                    ]
                ]
            ];
            
            // Add repeat instance if applicable
            if ($repeat_instance > 1) {
                $saveParams['data'][$record][$event_id]['redcap_repeat_instance'] = $repeat_instance;
                $saveParams['data'][$record][$event_id]['redcap_repeat_instrument'] = $instrument;
            }
            
            \REDCap::saveData($saveParams);
        }
    }

        /**
         * Hook : redcap_data_entry_form
         * Hide encrypted values in data entry forms
         */
    public function redcap_data_entry_form($project_id, $record, $instrument, $event_id, $group_id, $repeat_instance)
    {
        // Get list of fields that need encryption
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        
        // If no fields to encrypt, exit early
        if (empty($fieldsToEncrypt)) {
            return;
        }
        
        // Build JavaScript to mask encrypted fields
        $js = "<script type='text/javascript'>
        $(document).ready(function() {
            // Fields to mask
            var fieldsToMask = " . json_encode($fieldsToEncrypt) . ";
            
            // Loop through each field
            fieldsToMask.forEach(function(fieldName) {
                // Find the input element
                var input = $('input[name=\"' + fieldName + '\"]');
                
                if (input.length > 0) {
                    var currentValue = input.val();
                    
                    // Check if value is encrypted (starts with ENC:)
                    if (currentValue && currentValue.startsWith('ENC:')) {
                        // Replace value with placeholder
                        input.val('[ENCRYPTED - Hidden for Privacy]');
                        
                        // Make field read-only
                        input.prop('readonly', true);
                        
                        // Add visual styling
                        input.css({
                            'background-color': '#f0f0f0',
                            'color': '#666',
                            'font-style': 'italic'
                        });
                    }
                }
            });
        });
        </script>";
        
        // Output the JavaScript
        echo $js;
    }
    /**
     * Hook : redcap_survey_page
     * Hide encrypted values on survey pages
     */
    public function redcap_survey_page($project_id, $record, $instrument, $event_id, $group_id, $survey_hash, $response_id, $repeat_instance)
    {
        // Get list of fields that need encryption
        $fieldsToEncrypt = $this->getFieldsToEncrypt($project_id);
        
        // If no fields to encrypt, exit early
        if (empty($fieldsToEncrypt)) {
            return;
        }
        
        // Build JavaScript to mask encrypted fields
        $js = "<script type='text/javascript'>
        $(document).ready(function() {
            // Fields to mask
            var fieldsToMask = " . json_encode($fieldsToEncrypt) . ";
            
            // Loop through each field
            fieldsToMask.forEach(function(fieldName) {
                // Find the input element
                var input = $('input[name=\"' + fieldName + '\"]');
                
                if (input.length > 0) {
                    var currentValue = input.val();
                    
                    // Check if value is encrypted (starts with ENC:)
                    if (currentValue && currentValue.startsWith('ENC:')) {
                        // Replace value with placeholder
                        input.val('[ENCRYPTED - Hidden for Privacy]');
                        
                        // Make field read-only
                        input.prop('readonly', true);
                        
                        // Add visual styling
                        input.css({
                            'background-color': '#f0f0f0',
                            'color': '#666',
                            'font-style': 'italic'
                        });
                    }
                }
            });
        });
        </script>";
        
        // Output the JavaScript
        echo $js;
    }

    /**
     * Hook : redcap_email
     */
        public function redcap_email($to, $from, $subject, $message, $cc, $bcc, $fromName, $attachments)
    {
        // Check if recipient is encrypted
        if (strpos($to, 'ENC:') === 0) {
            try {
                // Decrypt the recipient address
                $decryptedTo = $this->decryptValue($to);
                
                // Send email with decrypted address using REDCap's email function
                \REDCap::email($decryptedTo, $from, $subject, $message, $cc, $bcc, $fromName, $attachments);
                
                // Return FALSE to prevent REDCap from sending again with encrypted address
                return false;
                
            } catch (\Exception $e) {
                // Log error but don't break email system
                \REDCap::logEvent(
                    "Field Encryption Module Error",
                    "Failed to decrypt email address: " . $e->getMessage(),
                    null,
                    null,
                    null,
                    $this->getProjectId()
                );
                
                // Return TRUE to let REDCap try to send anyway 
                return true;
            }
        }
        
        // Not encrypted - let REDCap handle normally
        return true;
    }
}
