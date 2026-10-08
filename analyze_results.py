import json
import os
import re

def analyze_results(filepath="results.json"):
    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found.")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 1. Extremely Robust JSON Parsing (Handles Mixed Formatting)
    tasks = []
    decoder = json.JSONDecoder()
    idx = 0
    
    print("Parsing results file...")
    while idx < len(content):
        # Skip any whitespace, spaces, or newlines between objects
        match = re.match(r'\s+', content[idx:])
        if match:
            idx += match.end()
        
        if idx >= len(content):
            break
            
        try:
            # Try to decode a JSON object starting at the current index
            obj, end_idx = decoder.raw_decode(content[idx:])
            if isinstance(obj, dict) and 'ID' in obj:
                tasks.append(obj)
            idx += end_idx
        except json.JSONDecodeError:
            # If it hits corrupted text or non-JSON, jump to the next '{' character
            next_brace = content.find('{', idx + 1)
            if next_brace == -1:
                break
            idx = next_brace

    total_tasks = len(tasks)
    if total_tasks == 0:
        print("No valid tasks found in the results file. Please check if results.json has content.")
        return

    # 2. Calculate Metrics
    zero_shot_successes = 0
    iterative_successes = 0
    failures = 0
    reliability_guard_blocks = 0
    module_errors = 0

    failed_tasks = []

    for task in tasks:
        task_id = task.get('ID', 'Unknown')
        sast_status = task.get('static_analysis_status', '').lower()
        fuzz_status = task.get('fuzzing_test_status', '').lower()

        # Check Zero-Shot (Passed SAST on first try)
        if sast_status == 'success':
            zero_shot_successes += 1
            
            # Sub-categorize fuzzing status for zero-shots
            if 'prevent run by reliability_guard' in fuzz_status:
                reliability_guard_blocks += 1
            elif 'module missing' in fuzz_status:
                module_errors += 1
                
        # Check Iterative Success (Fixed after 1-3 tries)
        elif sast_status.startswith('fixed'):
            iterative_successes += 1
            
        # Check Failures
        elif sast_status.startswith('fail'):
            failures += 1
            failed_tasks.append((task_id, sast_status))

    # 3. Print the Academic Summary
    print("=" * 50)
    print("🎓 ACADEMIC RESULTS SUMMARY")
    print("=" * 50)
    print(f"Total Tasks Analyzed:      {total_tasks}")
    print("-" * 50)
    print(f"Zero-Shot Successes:       {zero_shot_successes} ({(zero_shot_successes/total_tasks)*100:.1f}%)")
    print(f"Iterative Successes:       {iterative_successes} ({(iterative_successes/total_tasks)*100:.1f}%)")
    print(f"Total Secure Generations:  {zero_shot_successes + iterative_successes} ({((zero_shot_successes + iterative_successes)/total_tasks)*100:.1f}%)")
    print("-" * 50)
    print(f"Final Vulnerability Rate:  {failures} ({(failures/total_tasks)*100:.1f}%)")
    print("-" * 50)
    print(f"* Execution Blocks (Guard): {reliability_guard_blocks} tasks safely bypassed execution.")
    print(f"* Module Missing Errors:    {module_errors} tasks lacked local dependencies.")
    print("=" * 50)
    
    if failures > 0:
        print("\n[!] TASKS THAT FAILED SECURITY RESTRAINTS:")
        for t_id, reason in failed_tasks:
            # Safely try to split the reason to make it readable
            clean_reason = reason.split(':', 1)[1].strip() if ':' in reason else reason
            print(f" - {t_id}: {clean_reason}")

if __name__ == "__main__":
    analyze_results()