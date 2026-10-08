import os
import json
# Import the fully configured openai module and model from AutoSafeCoder's utils
from utils import openai, model 

def load_stride_prompts():
    """Reads the STRIDE GPT instructions you copied into the project."""
    prompt_dir = "stage0_prompts"
    files_to_load = ["base.md", "mitre_enterprise.md", "quick_base.md"]
    combined_instructions = ""
    
    for filename in files_to_load:
        filepath = os.path.join(prompt_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                combined_instructions += f.read() + "\n\n"
        else:
            print(f"Warning: {filename} not found in {prompt_dir}/")
            
    return combined_instructions

def generate_sdc_document(functional_prompt):
    """Stage 0: Generates the Security Design Context (SDC) from a user prompt."""
    print("\n[Stage 0] Generating Threat Model & Attack Tree via OpenAI...")
    
    stride_instructions = load_stride_prompts()
    
    json_schema_enforcement = """
    IMPORTANT: You must output your threat model ONLY as a valid JSON object.
    Do not include any conversational text outside the JSON.
    The JSON must strictly follow this exact structure:
    {
      "component_description": "Brief summary of the component being built",
      "attacker_goal": "The primary objective of an attacker",
      "attack_paths": [
        {
          "path_id": "PATH-1",
          "description": "Step-by-step scenario of the exploit",
          "type": "OR",
          "cwe_targets": [
            {
              "cwe_class": "CWE-89",
              "name": "SQL Injection",
              "mitre_attack": "T1190"
            }
          ],
          "defensive_requirements": ["Specific coding practice to mitigate this"]
        }
      ],
      "priority_requirements": ["Top priority defense 1", "Top priority defense 2"]
    }
    """
    
    system_instruction = stride_instructions + "\n" + json_schema_enforcement
    
    try:
        response = openai.chat.completions.create(
            model=model, 
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": f"Create a threat model for this programming requirement:\n{functional_prompt}"}
            ],
            temperature=0.2
        )
        
        raw_json = json.loads(response.choices[0].message.content)
        
        # Build Markdown Output
        sdc = "### SECURITY DESIGN CONTEXT\n"
        
        # 1. Component Description & Attacker Goal (with intelligent defaults)
        component = raw_json.get('component_description') or "Flask User Profile Database Endpoint"
        goal = raw_json.get('attacker_goal') or "Unauthorized access, data tampering, or service disruption via URL/database exploitation"
        
        sdc += f"**Component Focus:** {component}\n"
        sdc += f"**Root Attacker Goal:** {goal}\n\n"
        
        sdc += "#### IDENTIFIED ATTACK PATHS & THREAT MODEL:\n"
        
        # 2. Parse Attack Paths (Handles both custom schema and general STRIDE array)
        if "attack_paths" in raw_json and raw_json["attack_paths"]:
            for path in raw_json["attack_paths"]:
                sdc += f"* **{path.get('path_id', 'PATH')} ({path.get('type', 'OR')}):** {path.get('description')}\n"
                for cwe in path.get("cwe_targets", []):
                    sdc += f"  - **Target Class:** {cwe.get('cwe_class')} — {cwe.get('name')} [MITRE: {cwe.get('mitre_attack', 'N/A')}]\n"
                for defense in path.get("defensive_requirements", []):
                    sdc += f"  - **Mandatory Mitigation:** {defense}\n"
                    
        elif "threat_model" in raw_json:
            # Fallback parser for STRIDE threat objects
            for idx, threat in enumerate(raw_json["threat_model"], start=1):
                t_type = threat.get("Threat Type", "General Threat")
                scenario = threat.get("Scenario", "N/A")
                impact = threat.get("Potential Impact", "N/A")
                
                sdc += f"* **PATH-{idx} ({t_type.upper()}):** {scenario}\n"
                sdc += f"  - **Potential Impact:** {impact}\n"
                
        # 3. Parse Priority Requirements / Improvement Suggestions
        sdc += "\n#### HIGH-PRIORITY SECURITY REQUIREMENTS:\n"
        requirements = raw_json.get("priority_requirements") or raw_json.get("improvement_suggestions") or []
        for req in requirements:
            sdc += f"- {req}\n"
            
        return sdc
        
    except Exception as e:
        print(f"Error during Stage 0 generation: {e}")
        return "SECURITY DESIGN CONTEXT GENERATION FAILED."