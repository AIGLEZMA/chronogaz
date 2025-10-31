import os
import json
import argparse
import sys
from openai import OpenAI
from typing import List, Dict, Any, Optional

# --- Constants ---
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat" 
# Use a lower temperature for factual, template-based output
LLM_TEMPERATURE = 0.2

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Generate security policies from scan reports using the DeepSeek LLM.")
    parser.add_argument('--sast-report', help="Path to the unified SAST report JSON.", required=True)
    parser.add_argument('--sca-report', help="Path to the unified SCA report JSON.", required=True)
    parser.add_argument('--dast-report', help="Path to the unified DAST report JSON.", required=True)
    parser.add_argument('--output-dir', help="Directory to save the generated policy.", required=True)
    return parser.parse_args()

def load_json_report(file_path: str) -> Optional[Dict[str, Any]]:
    """Loads a JSON report file with error handling."""
    print(f"  > Loading report: {file_path}")
    if not os.path.exists(file_path):
        print(f"  ! WARNING: Report file not found: {file_path}. Skipping.", file=sys.stderr)
        return None
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            if not content:
                print(f"  ! WARNING: Report file is empty: {file_path}. Skipping.", file=sys.stderr)
                return None
            data = json.loads(content)
        print(f"  ✓ Report loaded successfully.")
        return data
    except json.JSONDecodeError:
        print(f"  ! WARNING: Failed to decode JSON from {file_path}. File might be corrupt. Skipping.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  ! WARNING: An unexpected error occurred while loading {file_path}: {e}", file=sys.stderr)
        return None

def extract_top_vulnerabilities(data: Optional[Dict[str, Any]], source_name: str) -> List[Dict[str, str]]:
    """Extracts 'top_vulnerabilities' from a report and standardizes them."""
    if not data:
        return []

    top_vulns_list = data.get('top_vulnerabilities', [])
    if not top_vulns_list:
        # Fallback to all vulnerabilities if top_vulnerabilities is empty
        top_vulns_list = data.get('vulnerabilities', [])

    standardized_vulns = []
    for item in top_vulns_list:
        # Use .get() for safe access
        name = item.get('name', item.get('ruleId', 'Unnamed Vulnerability'))
        description = item.get('description', item.get('message', 'No description provided.'))
        severity = item.get('severity', 'Medium')
        
        standardized_vulns.append({
            "name": name,
            "description": description,
            "severity": severity,
            "source": source_name
        })
    print(f"  ✓ Extracted {len(standardized_vulns)} vulnerabilities from {source_name}.")
    return standardized_vulns

def generate_policy_for_vulnerability(client: OpenAI, vulnerability: Dict[str, str]) -> Optional[str]:
    """
    Makes an API call to DeepSeek to generate a single, formatted policy
    for a specific vulnerability.
    """
    
    # 1. Define the AI's role
    system_prompt = """
    You are a senior Governance, Risk, and Compliance (GRC) analyst.
    Your task is to generate a single, concise security policy for a *specific vulnerability* provided by the user.
    You MUST follow the output structure and formatting requirements *exactly* as specified in the user's instructions.
    Do not add any conversational text. Generate *only* the policy text in the requested format.
    """

    # 2. Define the specific task and provide the data
    user_prompt = f"""
    **Vulnerability Data:**
    - **Name:** {vulnerability['name']}
    - **Description:** {vulnerability['description']}
    - **Source:** {vulnerability['source']}
    - **Severity:** {vulnerability['severity']}

    **Instructions:**
    Based *only* on the vulnerability data above, generate a security policy document.
    You MUST use the following format exactly:

    **Policy Title:** [Create a specific title for this vulnerability, e.g., "{vulnerability['name']} Prevention Policy"]

    **NIST CSF Reference:** [Fill in a relevant NIST CSF function, e.g., "PR.DS-5"]

    **ISO 27001 Reference:** [Fill in a relevant ISO control, e.g., "A.14.2.1"]

    **Risk Level:** [{vulnerability['severity'].upper()}]

    **Policy Statement:**
    [Write a 1-2 sentence high-level policy statement to mitigate this *specific* risk.]

    **Implementation Requirements:**
    [List 3-5 *specific* technical and procedural controls to implement this policy. Be actionable.]
    1.
    2.
    3.

    **Verification Method:**
    [List 2-3 methods to *verify* that the policy is working and the vulnerability is fixed, e.g., "SAST scanning on commit...", "DAST scanning quarterly..."]
    """

    # 3. Call the API
    try:
        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            max_tokens=1024,
            temperature=LLM_TEMPERATURE
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  ! ERROR: API call failed for vulnerability '{vulnerability['name']}': {e}", file=sys.stderr)
        return None

def main():
    """Main function to run the policy generation process."""
    print("--- Starting LLM Policy Generation Script ---")

    # 1. Get API Key
    api_key = os.environ.get('DEEPSEEK_API_KEY')
    if not api_key:
        print("FATAL ERROR: DEEPSEEK_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
    print("✓ DEEPSEEK_API_KEY found.")

    # 2. Initialize API Client
    try:
        client = OpenAI(api_key=api_key, base_url=DEEPSEEK_BASE_URL)
        print(f"✓ OpenAI client initialized for DeepSeek (Model: {DEEPSEEK_MODEL})")
    except Exception as e:
        print(f"FATAL ERROR: Failed to initialize OpenAI client: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Parse Arguments
    args = parse_arguments()
    print(f"✓ Arguments parsed. Output directory: {args.output_dir}")

    # 4. Load Reports & Extract Vulnerabilities
    print("\nLoading vulnerability reports...")
    sast_data = load_json_report(args.sast_report)
    sca_data = load_json_report(args.sca_report)
    dast_data = load_json_report(args.dast_report)
    
    print("\nExtracting top vulnerabilities...")
    sast_vulns = extract_top_vulnerabilities(sast_data, "SAST")
    sca_vulns = extract_top_vulnerabilities(sca_data, "SCA")
    dast_vulns = extract_top_vulnerabilities(dast_data, "DAST")
    
    all_top_vulnerabilities = sast_vulns + sca_vulns + dast_vulns

    if not all_top_vulnerabilities:
        print("! No top vulnerabilities found in any report. Exiting cleanly.")
        # We'll still write a file so the pipeline artifact step doesn't fail
        all_policies_text = "# Security Policy Report\n\nNo top vulnerabilities were found in the scans."
    else:
        print(f"✓ Found {len(all_top_vulnerabilities)} total top vulnerabilities to process.")

        # 5. Generate Policies in a Loop
        print("\nGenerating policies (this may take a moment)...")
        generated_policies = []
        for i, vuln in enumerate(all_top_vulnerabilities, 1):
            print(f"  > Processing vulnerability {i}/{len(all_top_vulnerabilities)}: {vuln['name']} ({vuln['severity']})")
            
            policy_text = generate_policy_for_vulnerability(client, vuln)
            
            if policy_text:
                generated_policies.append(policy_text)
                print(f"  ✓ Policy generated for {vuln['name']}.")
            else:
                print(f"  ! WARNING: Failed to generate policy for {vuln['name']}.", file=sys.stderr)

        print("✓ All policies generated.")
        
        # 6. Combine Policies into one file
        # Join each policy with a horizontal rule for readability
        all_policies_text = "\n\n---\n\n".join(generated_policies)
        
        if not all_policies_text:
             all_policies_text = "# Security Policy Report\n\nTop vulnerabilities were found, but the LLM failed to generate policies."

    # 7. Save the Output
    print("\nSaving final policy document...")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except Exception as e:
        print(f"FATAL ERROR: Could not create output directory {args.output_dir}: {e}", file=sys.stderr)
        sys.exit(1)

    output_filename = os.path.join(args.output_dir, "deepseek_generated_policies.md")
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(all_policies_text)
        print(f"✓ Policies successfully saved to: {output_filename}")
    except Exception as e:
        print(f"FATAL ERROR: Could not write policy to file: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- LLM Policy Generation Script Finished ---")


if __name__ == "__main__":
    main()

