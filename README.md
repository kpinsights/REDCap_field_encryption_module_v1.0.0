# REDCap Field Encryption Module

A REDCap External Module that encrypts sensitive field values (like email addresses) while maintaining support for automated survey invitations.

## The Problem

Many research projects use automated survey invitations - whether for longitudinal follow-ups, triggered surveys based on participant responses, or scheduled reminders. This creates a privacy challenge: how do you enable automated invitations without exposing participant contact information to researchers?

REDCap stores email addresses in plain text by default. Anyone with data access can view them, compromising participant anonymity.

## The Solution

This module encrypts sensitive fields so researchers cannot access them, while automated survey invitations continue to function normally.

How it works:

1. Add `@ENCRYPT` action tag to sensitive fields (typically email)
2. Participant submits the survey with their email
3. The module automatically encrypts it - researchers see `[ENCRYPTED - Hidden for Privacy]`
4. A background cron job decrypts the email when sending survey invitations
5. Participant receives the survey link at their actual email address

Privacy is maintained, automation keeps working.

## Features

- Encrypts any field type (email, phone, text) using the `@ENCRYPT` action tag
- Supports automated survey invitations with encrypted emails (currently email only, not SMS)
- Uses SaferCrypto for strong authenticated encryption (AES-256-GCM + HMAC)
- Encrypted emails stored as `ENC_[base64]@xx.xx` to satisfy REDCap's validation
- Compatible with longitudinal projects and multiple events
- Masks encrypted values in data entry forms, reports, exports, and survey pages
- Cron runs every 30 seconds - even "immediate" invitations are delivered quickly
- Secure logging that never includes decrypted values
- Works with existing REDCap survey scheduler workflow

## Requirements

- REDCap 15.0.0 or higher
- PHP 7.4.0 or higher
- Working mail delivery system (Postfix, sendmail, or SMTP)

## Installation

1. Place the module in your REDCap `modules` directory
2. Navigate to Control Center → External Modules
3. Enable "REDCap Field Encryption Module"
4. Configure the Master Encryption Key (generate a strong random key, minimum 32 characters)
5. Enable the module for your project

**Important:** Store your encryption key securely. Lost keys mean permanently inaccessible encrypted data.

## Configuration

### Setting Up Encrypted Fields

1. Go to Project Setup → Designer
2. Edit the field you want to encrypt
3. Add `@ENCRYPT` to the Action Tags 
4. Save

Fields encrypt automatically when participants submit data.

### Configuring Automated Survey Invitations

Set up automated invitations the same way you normally would in REDCap. Just select your encrypted email field as the recipient. The module's cron job handles decryption and delivery automatically.

Note: The module replaces both `[survey-link]` and `[survey-url]` placeholders in your email templates with the actual survey link.

### Email Delivery Requirements

Your REDCap instance must have a functioning mail delivery system. Most production environments already have Postfix or SMTP configured. If emails fail to send, verify mail configuration in Control Center → General Configuration or consult your REDCap documentation.

## Technical Details

### Encryption Process

When a participant submits a form containing an `@ENCRYPT` field:

1. The `redcap_save_record` hook triggers after the save operation
2. Module identifies fields with the `@ENCRYPT` tag
3. Values are encrypted using SaferCrypto (AES-256-GCM with HMAC)
4. Encrypted output is base64-encoded using URL-safe characters
5. Email fields are formatted as `ENC_[base64]@xx.xx` to pass REDCap validation
6. Encrypted values replace plain text in the database
7. Participant records are updated with encrypted email addresses

### Automated Invitation Delivery

The delivery process:

1. REDCap queues survey invitations containing encrypted email addresses
2. Module cron executes every 30 seconds
3. Queries identify invitations ready for delivery with emails matching pattern `ENC_%@xx.xx`
4. Email addresses are decrypted
5. Unique survey links are generated using participant hashes
6. Placeholders `[survey-link]` (clickable) and `[survey-url]` (plain text) are replaced in email templates
7. Emails are sent via REDCap's email function
8. Queue status is updated to 'SENT' with timestamp

The cron is necessary because REDCap cannot send to fake addresses like `ENC_xyz@xx.xx`. The module intercepts these invitations, decrypts the real addresses, and completes delivery successfully.


## Security Considerations

The master encryption key is stored in REDCap system settings. Direct database access reveals encrypted values, but decryption requires the key.

The module logs operational activities for debugging purposes but never logs decrypted values. Only record IDs, survey IDs, and status information appear in logs.

After decryption, emails are sent in plain text. Ensure your mail server uses TLS for transport security.

Encrypted data in backups requires the same encryption key for decryption.


## Authors

Kshitiz Pokhrel \\
kpokhrel@torontomu.ca \\
CERC in Health Equity & Community Well-Being, Toronto Metropolitan University

Ryan McRonald \\
rmcronald@uvic.ca \\
University of Victoria

## Version

v1.0.0 - Initial release
