import os
import json
import argparse
import sys
from openai import OpenAI
from typing import List, Dict, Any, Optional

# --- Constants ---

# DeepSeek Configuration
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat" 

# LLaMA (Together.ai) Configuration
LLAMA_BASE_URL = "https://api.together.xyz/v1"
LLAMA_MODEL = "meta-llama/Llama-3.3-70B-Instruct-Turbo"

# General LLM Settings
LLM_TEMPERATURE = 0.2
API_TIMEOUT = 30.0  # 30-second timeout for each API call

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Generate security policies from scan reports using DeepSeek and LLaMA.")
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

def extract_policy_title(policy_text: str) -> str:
    """Helper function to extract the title from a generated policy string."""
    try:
        for line in policy_text.splitlines():
            if line.startswith("**Policy Title:**"):
                # Get text after the markdown, strip whitespace
                return line.replace("**Policy Title:**", "").strip()
    except Exception:
        pass # Fallback on error
    # Fallback if no title is found or text is malformed
    return "Untitled Policy"

def generate_policy_for_vulnerability(
    client: OpenAI, 
    model_name: str, 
    vulnerability: Dict[str, str]
) -> Optional[str]:
    """
    Makes an API call to a given model to generate a single, formatted policy
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
        print(f"    > Sending API request to model: '{model_name}' for vuln: '{vulnerability['name']}'...")
        response = client.chat.completions.create(
            model=model_name, # Use the model_name passed to the function
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            max_tokens=1024,
            temperature=LLM_TEMPERATURE,
            timeout=API_TIMEOUT
        )
        print(f"    ✓ API response received from: '{model_name}'.")
        return response.choices[0].message.content
    except Exception as e:
        print(f"  ! ERROR: API call to {model_name} failed for vulnerability '{vulnerability['name']}': {e}", file=sys.stderr)
        return None

def save_policy_file(output_dir: str, filename: str, policies: List[str]):
    """
    Saves a list of generated policies to a file,
    consolidating duplicates and adding notes.
    """
    
    print(f"\n  Consolidating policies for {filename}...")
    
    if not policies:
         policy_text = f"# Security Policy Report ({filename})\n\nNo policies were generated."
    else:
        # --- DE-DUPLICATION LOGIC ---
        policy_groups: Dict[str, List[str]] = {}
        
        # 1. Group policies by their extracted title
        for policy in policies:
            title = extract_policy_title(policy)
            if title not in policy_groups:
                policy_groups[title] = []
            policy_groups[title].append(policy)
        
        print(f"  ✓ Found {len(policies)} total policies, consolidated into {len(policy_groups)} unique groups.")

        # 2. Build the final text
        consolidated_policies = []
        for title, group in policy_groups.items():
            # Take the first policy as the canonical one
            canonical_policy = group[0]
            count = len(group)
            
            if count > 1:
                # Add the note as requested by the user
                note = f"\n\n**Consolidation Note:** {count - 1} other similar issue(s) were also detected and are covered by this policy."
                canonical_policy += note
                
            consolidated_policies.append(canonical_policy)
        
        # Join each consolidated policy with a horizontal rule
        policy_text = "\n\n---\n\n".join(consolidated_policies)

    output_filename = os.path.join(output_dir, filename)
    
    try:
        with open(output_filename, 'w', encoding='utf-8') as f:
            f.write(policy_text)
        print(f"✓ Policies successfully saved to: {output_filename}")
    except Exception as e:
        print(f"FATAL ERROR: Could not write policy to file {output_filename}: {e}", file=sys.stderr)
        # We don't exit(1) here, to allow the *other* model's file to still be saved.

def main():
    """Main function to run the policy generation process."""
    print("--- Starting LLM Policy Generation Script ---")

    # 1. Get API Keys
    deepseek_api_key = os.environ.get('DEEPSEEK_API_KEY')
    together_api_key = os.environ.get('TOGETHER_API_KEY')

    if not deepseek_api_key:
        print("FATAL ERROR: DEEPSEEK_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
    if not together_api_key:
        print("FATAL ERROR: TOGETHER_API_KEY environment variable not set.", file=sys.stderr)
        sys.exit(1)
        
    print("✓ API keys for DeepSeek and Together.ai found.")

    # 2. Initialize API Clients
    try:
        client_deepseek = OpenAI(api_key=deepseek_api_key, base_url=DEEPSEEK_BASE_URL)
        print(f"✓ OpenAI client initialized for DeepSeek (Model: {DEEPSEEK_MODEL})")
        
        client_llama = OpenAI(api_key=together_api_key, base_url=LLAMA_BASE_URL)
        print(f"✓ OpenAI client initialized for LLaMA (Model: {LLAMA_MODEL})")
        
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
        # Create the output directory anyway
        os.makedirs(args.output_dir, exist_ok=True)
        save_policy_file(args.output_dir, "deepseek_generated_policies.md", [])
        save_policy_file(args.output_dir, "llama_generated_policies.md", [])
        print("\n--- LLM Policy Generation Script Finished ---")
        sys.exit(0)
        
    print(f"✓ Found {len(all_top_vulnerabilities)} total top vulnerabilities to process.")

    # 5. Generate Policies in a Loop (for both models)
    print("\nGenerating policies (this may take a moment)...")
    generated_policies_deepseek = []
    generated_policies_llama = []

    for i, vuln in enumerate(all_top_vulnerabilities, 1):
        print(f"\n  > Processing vulnerability {i}/{len(all_top_vulnerabilities)}: {vuln['name']} ({vuln['severity']})")
        
        # --- Call DeepSeek ---
        policy_deepseek = generate_policy_for_vulnerability(client_deepseek, DEEPSEEK_MODEL, vuln)
        if policy_deepseek:
            generated_policies_deepseek.append(policy_deepseek)
        else:
            print(f"  ! WARNING: Failed to generate policy for {vuln['name']} using DeepSeek.", file=sys.stderr)

        # --- Call LLaMA ---
        policy_llama = generate_policy_for_vulnerability(client_llama, LLAMA_MODEL, vuln)
        if policy_llama:
            generated_policies_llama.append(policy_llama)
        else:
            print(f"  ! WARNING: Failed to generate policy for {vuln['name']} using LLaMA.", file=sys.stderr)

    print("\n✓ All policy generation attempts complete.")

    # 6. Save the Output
    print("\nSaving final policy documents...")
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except Exception as e:
        print(f"FATAL ERROR: Could not create output directory {args.output_dir}: {e}", file=sys.stderr)
        sys.exit(1)

    # Save DeepSeek policies
    save_policy_file(args.output_dir, "deepseek_generated_policies.md", generated_policies_deepseek)
    
    # Save LLaMA policies
    save_policy_file(args.output_dir, "llama_generated_policies.md", generated_policies_llama)

    print("\n--- LLM Policy Generation Script Finished ---")


if __name__ == "__main__":
    main()

