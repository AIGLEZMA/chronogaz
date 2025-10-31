import os
import json
import argparse
import sys
from openai import OpenAI

# --- Constants ---
DEEPSEEK_BASE_URL = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat" 

def parse_arguments():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description="Generate security policies from scan reports using the DeepSeek LLM.")
    parser.add_argument('--sast-report', help="Path to the unified SAST report JSON.", required=True)
    parser.add_argument('--sca-report', help="Path to the unified SCA report JSON.", required=True)
    parser.add_argument('--dast-report', help="Path to the unified DAST report JSON.", required=True)
    parser.add_argument('--output-dir', help="Directory to save the generated policy.", required=True)
    return parser.parse_args()

def load_json_report(file_path):
    """Loads a JSON report file with error handling."""
    print(f"  > Loading report: {file_path}")
    if not os.path.exists(file_path):
        print(f"  ! WARNING: Report file not found: {file_path}. Proceeding with empty data.", file=sys.stderr)
        return None # Return None, don't fail the whole job.
    
    try:
        with open(file_path, 'r') as f:
            # Handle empty files
            content = f.read()
            if not content:
                print(f"  ! WARNING: Report file is empty: {file_path}.", file=sys.stderr)
                return None
            data = json.loads(content)
        print(f"  ✓ Report loaded successfully.")
        return data
    except json.JSONDecodeError:
        print(f"  ! WARNING: Failed to decode JSON from {file_path}. File might be corrupt.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  ! WARNING: An unexpected error occurred while loading {file_path}: {e}", file=sys.stderr)
        return None

def get_report_summary(data, name):
    """Extracts key summary info from a report data structure."""
    if not data:
        return f"No {name} data provided or file was empty/corrupt.\n"
    
    # Use .get() to safely access keys that might not exist
    summary = data.get('summary', {})
    top_vulns = data.get('top_vulnerabilities', [])
    
    # Use .get() again for nested keys
    summary_text = f"""
    **{name} Report Summary:**
    - Total Vulnerabilities: {summary.get('total_vulnerabilities', 'N/A')}
    - Risk Score: {summary.get('risk_score', 'N/A')} / 100
    - Severity: {summary.get('severity_distribution', 'N/A')}
    
    **Top {name} Vulnerabilities (if any):**
    {json.dumps(top_vulns, indent=2) if top_vulns else "No top vulnerabilities listed."}
    """
    return summary_text

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
        print(f"✓ OpenAI client initialized for DeepSeek (Base URL: {DEEPSEEK_BASE_URL})")
    except Exception as e:
        print(f"FATAL ERROR: Failed to initialize OpenAI client: {e}", file=sys.stderr)
        sys.exit(1)

    # 3. Parse Arguments
    args = parse_arguments()
    print("Script arguments parsed:")
    print(f"  - SAST Report: {args.sast_report}")
    print(f"  - SCA Report: {args.sca_report}")
    print(f"  - DAST Report: {args.dast_report}")
    print(f"  - Output Dir: {args.output_dir}")

    # 4. Load Reports
    print("\nLoading vulnerability reports...")
    sast_data = load_json_report(args.sast_report)
    sca_data = load_json_report(args.sca_report)
    dast_data = load_json_report(args.dast_report)

    # 5. Construct Prompt
    print("\nConstructing prompt for LLM...")
    
    # Get summaries from the loaded data
    sast_summary = get_report_summary(sast_data, "SAST")
    sca_summary = get_report_summary(sca_data, "SCA")
    dast_summary = get_report_summary(dast_data, "DAST")

    # System prompt defines the AI's role
    system_prompt = "You are a world-class DevSecOps and GRC (Governance, Risk, Compliance) expert. Your task is to write a draft security policy to mitigate the vulnerabilities detected in a project."
    
    # User prompt provides the data and instructions
    user_prompt = f"""
    Please analyze the following vulnerability scan summaries from our project.
    
    --- BEGIN SAST REPORT ---
    {sast_summary}
    --- END SAST REPORT ---
    
    --- BEGIN SCA REPORT ---
    {sca_summary}
    --- END SCA REPORT ---
    
    --- BEGIN DAST REPORT ---
    {dast_summary}
    --- END DAST REPORT ---
    
    **INSTRUCTIONS:**
    Based *only* on the reports provided:
    1.  Write a draft security policy in Markdown format.
    2.  Focus on actionable, high-level controls that directly address the *types* of vulnerabilities found (e.g., "All user input must be sanitized...", "Dependency versions must be...").
    3.  If possible, reference relevant NIST (e.g., NIST SP 800-53) or ISO 27001 controls.
    4.  Keep the policy concise and ready for review by a security team.
    """
    
    print(f"✓ System Prompt: {system_prompt}")
    print(f"✓ User Prompt constructed (length: {len(user_prompt)} characters).")

    # 6. Call the API
    print(f"\nSending request to DeepSeek model: {DEEPSEEK_MODEL}...")
    try:
        response = client.chat.completions.create(
            model=DEEPSEEK_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=False,
            max_tokens=2048, # Give it enough room to write a policy
            temperature=0.3  # Lower temperature for more factual, less "creative" policies
        )
        
        policy_text = response.choices[0].message.content
        print("✓ Response received from DeepSeek.")
        
    except Exception as e:
        print(f"FATAL ERROR: API call failed: {e}", file=sys.stderr)
        sys.exit(1)

    # 7. Save the Output
    print("\nSaving generated policy...")
    
    # Create output directory if it doesn't exist
    try:
        os.makedirs(args.output_dir, exist_ok=True)
    except Exception as e:
        print(f"FATAL ERROR: Could not create output directory {args.output_dir}: {e}", file=sys.stderr)
        sys.exit(1)

    # Define a clear filename
    output_filename = os.path.join(args.output_dir, "deepseek_generated_policy.md")
    
    try:
        with open(output_filename, 'w') as f:
            f.write(policy_text)
        print(f"✓ Policy successfully saved to: {output_filename}")
    except Exception as e:
        print(f"FATAL ERROR: Could not write policy to file: {e}", file=sys.stderr)
        sys.exit(1)

    print("\n--- LLM Policy Generation Script Finished ---")


if __name__ == "__main__":
    main()
