# patterns.ps1
# Detection patterns for Document Scrubber - PowerShell Edition
# Mirrors the Python DETECTION_PATTERNS from qgis_scrub_master.py
# Author: Joey M. Woody P.E.
# Version: 1.0.2 - Fixed PHONE/PARCEL overlap, COMPANY partial matches, header false positives

# Each pattern has: regex, alias, description, case_insensitive flag
$script:DETECTION_PATTERNS = [ordered]@{
    
    # Email
    EMAIL = @{
        pattern = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        alias = '[EMAIL]'
        description = 'Email addresses'
        case_insensitive = $true
    }
    
    # Phone numbers - FIXED: Require at least one separator to avoid matching 10-digit parcel IDs
    # Matches: (843) 555-1234, 843-555-1234, 843.555.1234, 843 555 1234
    # Does NOT match: 1234567890 (pure digits)
    PHONE = @{
        pattern = '(?:\(\d{3}\)[-.\s]?\d{3}[-.\s]?\d{4}|\d{3}[-.\s]\d{3}[-.\s]?\d{4})'
        alias = '[PHONE]'
        description = 'Phone numbers (requires separator)'
        case_insensitive = $false
    }
    
    # Street addresses
    ADDRESS_STREET = @{
        pattern = '\d+\s+(?:[NSEW]\.?\s+)?[A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)*\s+(?:Street|St|Avenue|Ave|Road|Rd|Drive|Dr|Lane|Ln|Boulevard|Blvd|Court|Ct|Place|Pl|Way|Circle|Cir|Trail|Trl|Parkway|Pkwy)\.?(?:\s+(?:Suite|Ste|Apt|Unit|#)\s*\d+)?'
        alias = '[ADDRESS]'
        description = 'Street addresses'
        case_insensitive = $true
    }
    
    # Highway addresses
    ADDRESS_HIGHWAY = @{
        pattern = '\d+\s+(?:Highway|Hwy|Route|Rt|US|State Road|SR)\s+\d+[A-Z]?(?:\s+(?:Suite|Ste|Apt|Unit|#)\s*\d+)?'
        alias = '[ADDRESS]'
        description = 'Highway addresses'
        case_insensitive = $true
    }
    
    # PO Box
    ADDRESS_POBOX = @{
        pattern = 'P\.?O\.?\s*Box\s+\d+'
        alias = '[PO_BOX]'
        description = 'PO Box addresses'
        case_insensitive = $true
    }
    
    # City, State ZIP
    ADDRESS_CITY_STATE_ZIP = @{
        pattern = '[A-Z][a-zA-Z\s]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?'
        alias = '[CITY_STATE_ZIP]'
        description = 'City, State ZIP'
        case_insensitive = $false
    }
    
    # Names with titles
    NAME_TITLED = @{
        pattern = '(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+'
        alias = '[PERSON_NAME]'
        description = 'Names with titles'
        case_insensitive = $false
    }
    
    # Names with credentials
    NAME_CREDENTIALED = @{
        pattern = '[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+(?:,?\s*(?:P\.?E\.?|PLS|RLS|AICP|AIA|PG|RLA|LEED\s*AP|CFM|EIT|PhD|Jr\.?|Sr\.?|III|IV))+'
        alias = '[PERSON_NAME]'
        description = 'Names with credentials'
        case_insensitive = $false
    }
    
    # Names with middle initial
    NAME_MIDDLE_INITIAL = @{
        pattern = '[A-Z][a-z]+\s+[A-Z]\.\s+[A-Z][a-z]+'
        alias = '[PERSON_NAME]'
        description = 'Names with middle initial'
        case_insensitive = $false
    }
    
    # ALL CAPS names with credentials
    NAME_ALLCAPS_CREDENTIAL = @{
        pattern = '[A-Z]{2,}(?:\s+[A-Z]\.?)?\s+[A-Z]{2,}(?:,?\s*(?:P\.?E\.?|PLS|RLS|AICP|AIA|PG|RLA|CFM|EIT))+'
        alias = '[PERSON_NAME]'
        description = 'ALL CAPS names with credentials'
        case_insensitive = $false
    }
    
    # Contact Person field
    NAME_CONTACT_PERSON = @{
        pattern = 'Contact(?:\s+Person)?:\s*([A-Z][a-zA-Z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-zA-Z]+)'
        alias = '[CONTACT_NAME]'
        description = 'Contact Person field'
        case_insensitive = $true
    }
    
    # N/F owner names (survey)
    SURVEY_NF_OWNER = @{
        pattern = 'N/?F[:\s]+([A-Z][A-Z\s&.,]+?)(?=\s*(?:\(|$|\n|N/?F|PARCEL|LOT|BLOCK|TMS|DEED|PLAT))'
        alias = '[ADJACENT_OWNER]'
        description = 'N/F owner names'
        case_insensitive = $true
    }
    
    # Property Of names
    SURVEY_PROPERTY_OF = @{
        pattern = 'Property\s+Of[:\s]+([A-Z][A-Z\s&.,]+?)(?=\s*(?:\(|$|\n|PARCEL|LOT|TMS))'
        alias = '[PROPERTY_OWNER]'
        description = 'Property Of names'
        case_insensitive = $true
    }
    
    # Deed Book references
    SURVEY_DEED_BOOK = @{
        pattern = 'Deed\s+Book\s+[A-Z]?\d+[,\s]+Page\s+\d+'
        alias = '[DEED_REF]'
        description = 'Deed Book references'
        case_insensitive = $true
    }
    
    # Plat Cabinet references
    SURVEY_PLAT_CAB = @{
        pattern = 'Plat\s+(?:Cabinet|Book|Cab)\s+[A-Z]?\d*[,\s]+(?:Page|Slide)\s+\d+'
        alias = '[PLAT_REF]'
        description = 'Plat Cabinet references'
        case_insensitive = $true
    }
    
    # TMS numbers
    SURVEY_TMS = @{
        pattern = 'TMS[:#\s]+[\d-]+'
        alias = '[TMS_REF]'
        description = 'TMS references'
        case_insensitive = $true
    }
    
    # Long parcel numbers - FIXED: Require digit at start to avoid matching "PARCEL INFORMATION"
    SURVEY_PARCEL_NUM = @{
        pattern = 'Parcel\s*(?:#|No\.?|Number)?[:\s]*\d[\dA-Z-]{9,}'
        alias = '[PARCEL_ID]'
        description = 'Parcel numbers (long format)'
        case_insensitive = $true
    }
    
    # Subdivision names
    SURVEY_SUBDIVISION = @{
        pattern = '(?:Subdivision|Subdiv|S/D)[:\s]+([A-Z][A-Za-z\s]+?)(?=\s*(?:Phase|Section|Lot|Block|$|\n))'
        alias = '[SUBDIVISION]'
        description = 'Subdivision names'
        case_insensitive = $true
    }
    
    # Block/Lot references
    SURVEY_BLOCK_LOT = @{
        pattern = '(?:Block\s+\d+[,\s]+)?Lot\s+\d+[A-Z]?'
        alias = '[BLOCK_LOT]'
        description = 'Block/Lot references'
        case_insensitive = $true
    }
    
    # Surveying companies - FIXED: Require company suffix (Inc, LLC, etc.) to avoid partial matches
    # This prevents "County Surveyor's Office" from matching
    COMPANY_SURVEYING = @{
        pattern = '[A-Z][A-Za-z&\s]+(?:Surveying|Survey|Engineering|Engineers?|Land\s+Surveyors?)\s+(?:Inc\.?|LLC|LLP|Corp\.?|Co\.?|PC|PA|Associates|Group|Services|Consultants)'
        alias = '[COMPANY]'
        description = 'Surveying/Engineering companies (with suffix)'
        case_insensitive = $true
    }
    
    # Planning companies - FIXED: Require company suffix
    COMPANY_PLANNING = @{
        pattern = '[A-Z][A-Za-z&\s]+(?:Planning|Planners|Architecture|Architects?|Landscape)\s+(?:Inc\.?|LLC|LLP|Corp\.?|Co\.?|PC|PA|Associates|Group|Services|Consultants)'
        alias = '[COMPANY]'
        description = 'Planning/Architecture companies (with suffix)'
        case_insensitive = $true
    }
    
    # PE License numbers
    PE_LICENSE = @{
        pattern = 'P\.?E\.?\s*(?:#|No\.?|Number)?[:\s]*\d{4,6}'
        alias = '[PE_NUMBER]'
        description = 'PE License numbers'
        case_insensitive = $true
    }
    
    # PLS License numbers
    PLS_LICENSE = @{
        pattern = '(?:PLS|RLS)\s*(?:#|No\.?|Number)?[:\s]*\d{4,6}'
        alias = '[PLS_NUMBER]'
        description = 'PLS License numbers'
        case_insensitive = $true
    }
    
    # Permit IDs
    PERMIT_ID = @{
        pattern = '(?:Permit|CAA|NPDES|MS4)\s*(?:#|No\.?|ID)?[:\s]*[A-Z]{0,3}\d{4,}'
        alias = '[PERMIT_ID]'
        description = 'Permit/CAA numbers'
        case_insensitive = $true
    }
    
    # 10-digit Parcel IDs (standalone)
    PARCEL_ID = @{
        pattern = '(?<!\d)\d{10}(?!\d)'
        alias = '[PARCEL_ID]'
        description = '10-digit Parcel IDs'
        case_insensitive = $false
    }
    
    # Dashed Parcel IDs
    PARCEL_ID_DASHED = @{
        pattern = '\d{3}-\d{2}-\d{2}-\d{3}'
        alias = '[PARCEL_ID]'
        description = 'Dashed Parcel/Tax IDs'
        case_insensitive = $false
    }
    
    # SSN
    SSN = @{
        pattern = '(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)'
        alias = '[SSN_REDACTED]'
        description = 'Social Security Numbers'
        case_insensitive = $false
    }
    
    # GPS Coordinates
    COORDINATES = @{
        pattern = '-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}'
        alias = '[COORDINATES]'
        description = 'GPS coordinates'
        case_insensitive = $false
    }
}

# Variable $script:DETECTION_PATTERNS is available after dot-sourcing this file
