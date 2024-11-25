import xml.etree.ElementTree as ET

def parse_policy(file_path):
    """Parsa la policy XML e restituisce gli orari di lavoro."""
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        # Estrai regole di Allow e Deny
        allow_rule = root.find(".//Rule[@RuleId='AllowOperationDuringWorkingHours']")
        deny_rule = root.find(".//Rule[@RuleId='DenyOperationOutsideWorkingHours']")
        
        allow_start_time = allow_rule.find(".//AttributeValue[1]").text
        allow_end_time = allow_rule.find(".//AttributeValue[2]").text
        
        deny_start_time = deny_rule.find(".//AttributeValue[1]").text
        deny_end_time = deny_rule.find(".//AttributeValue[2]").text
        
        return {
            "allow": {"start": allow_start_time, "end": allow_end_time},
            "deny": {"start": deny_start_time, "end": deny_end_time},
        }
    except Exception as e:
        print(f"Error parsing policy: {e}")
        return None
