<?php
namespace CERCHECW\FieldEncryptionModule;

use ExternalModules\AbstractExternalModule;

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
        
        return hex2bin($keyHex);
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