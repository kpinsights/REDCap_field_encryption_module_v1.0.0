# REDCap Field Encryption Module

A REDCap External Module that automatically encrypts sensitive field values (like email addresses) to protect participant privacy REDCap Surveys. Encrypted fields are completely hidden from researchers but remain accessible to the system for automated survey invitations and notifications.

## Overview

This module addresses a critical privacy need in longitudinal research: **How do you send automated follow-up invitations without exposing participant contact information to researchers?**

**The Solution:**
- Add `@ENCRYPT` action tag to sensitive fields during survey design
- Participant enters email during enrollment
- Module automatically encrypts it on save
- Researchers see `[ENCRYPTED - Hidden for Privacy]` instead of the actual email
- REDCap's automated system can still decrypt and send survey invitations
- Maintains complete anonymity while enabling longitudinal follow-up