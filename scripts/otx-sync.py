import os
import sys
import re
import glob
from OTXv2 import OTXv2

def parse_md_file(filepath):
    """
    Parses a markdown file to extract the title, description, and IOCs.
    Assumes IOCs are in a Markdown table under '## Indicators of Compromise'.
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract title from front matter or first H1
    title_match = re.search(r'^title:\s*"(.*?)"', content, re.MULTILINE)
    if not title_match:
        title_match = re.search(r'^#\s+(.*)$', content, re.MULTILINE)
    title = title_match.group(1) if title_match else os.path.basename(filepath)

    # Extract description from front matter
    desc_match = re.search(r'^description:\s*"(.*?)"', content, re.MULTILINE)
    description = desc_match.group(1) if desc_match else "Indicators of Compromise from Meta Threat Research"

    # Extract IOCs from the table
    # Look for the table after the "## Indicators of Compromise" header
    iocs = []
    ioc_section = re.split(r'##\s+Indicators of Compromise', content, flags=re.IGNORECASE)
    if len(ioc_section) > 1:
        # Get the text between IOC header and the next header (or end of file)
        table_text = re.split(r'\n##\s+', ioc_section[1])[0]
        
        # Find all table rows (lines starting with |)
        rows = re.findall(r'^\|(.*?)\|$', table_text, re.MULTILINE)
        
        # Skip header and separator rows
        for row in rows[2:]:
            cols = [c.strip() for c in row.split('|')]
            if len(cols) >= 2:
                ind_type = cols[0]
                ind_value = cols[1]
                
                # Clean up markdown code blocks and defanged URLs
                ind_value = ind_value.replace('`', '').replace('[.]', '.')
                
                # Map to OTX types
                otx_type = None
                if ind_type.upper() == 'URL':
                    otx_type = 'URL'
                elif ind_type.upper() in ['DOMAIN', 'HOSTNAME']:
                    otx_type = 'domain'
                elif ind_type.upper() in ['IPV4', 'IP']:
                    otx_type = 'IPv4'
                elif ind_type.upper() == 'IPV6':
                    otx_type = 'IPv6'
                elif ind_type.upper() in ['SHA256', 'SHA-256']:
                    otx_type = 'FileHash-SHA256'
                elif ind_type.upper() in ['MD5']:
                    otx_type = 'FileHash-MD5'
                
                if otx_type:
                    iocs.append({
                        'indicator': ind_value,
                        'type': otx_type
                    })

    return {
        'name': title,
        'description': description,
        'indicators': iocs,
        'tags': ['Meta', 'ThreatResearch', 'CIB']
    }

def sync_to_otx(api_key, md_files):
    otx = OTXv2(api_key)
    
    # Get all existing pulses for the user to check if we need to create or update
    print("Fetching existing pulses...")
    try:
        # get_my_pulses doesn't exist in all versions, so we search by author
        # A simpler approach is to just try creating, and if we want to update, we'd need the pulse ID.
        # For this script, we will create a new pulse if it has IOCs.
        # Note: OTX API doesn't easily let you search your own pulses by exact name without pagination.
        # We will create new pulses. If the user wants to update, they should store the Pulse ID in the MD file.
        pass
    except Exception as e:
        print(f"Warning: {e}")

    for filepath in md_files:
        print(f"Processing {filepath}...")
        data = parse_md_file(filepath)
        
        if not data['indicators']:
            print(f"  No IOCs found in {filepath}. Skipping.")
            continue
            
        print(f"  Found {len(data['indicators'])} IOCs. Creating pulse: {data['name']}")
        
        try:
            response = otx.create_pulse(
                name=data['name'],
                public=True,
                description=data['description'],
                indicators=data['indicators'],
                tags=data['tags']
            )
            print(f"  Success! Pulse created: {response.get('id', 'Unknown ID')}")
        except Exception as e:
            print(f"  Error creating pulse: {e}")

if __name__ == "__main__":
    api_key = os.environ.get('OTX_API_KEY')
    if not api_key:
        print("Error: OTX_API_KEY environment variable not set.")
        sys.exit(1)
        
    # Find all markdown files in the indicators directory
    indicator_files = glob.glob('indicators/*.md')
    if not indicator_files:
        print("No markdown files found in indicators/ directory.")
        sys.exit(0)
        
    sync_to_otx(api_key, indicator_files)
