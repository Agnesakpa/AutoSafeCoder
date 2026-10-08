from executor_agent_safe import FResult, execute_fuzz
from programmer_agent import ProgrammerAgent
from tester_fuzz_agent import TesterFuzzAgent
from fuzz_agent import InputMutatorAgent
from executor_static import ExecutorStaticAgent
from datasets import load_dataset
from stage0_design import generate_sdc_document
import json
import os 
import time
import re  # Added for Regex logic

class MultiAgentSystem:
    def __init__(self, entry):
        self.programmer_agent = ProgrammerAgent(entry)
        self.tester_fuzz_agent = TesterFuzzAgent(entry)
        self.executor_static = ExecutorStaticAgent(entry)
        self.code = None
        self.test_inputs = None
        self.entry = entry # Store entry for the run method

    # NOTE: Reduced iterations from 120 to 5 to protect your $5 budget!
    def run(self, iterations=5):
        entry = self.entry
        # Step 1: Programmer writes code
        self.code = self.programmer_agent.write_code()
        print(f"Programmer's Code:\n{self.code}")
        
        problems = {}
        # Add the entry to the dictionary
        problems[entry['ID']] = {'ID': entry['ID']}
        #Step 2: Static analyzer agent reviews code
        result, error_description = self.executor_static.execute_static_analysis_gpt(self.code)

        print('result')
        print(result)
        # If error, give feedback to programmer agent up to 3 times
        if result.name != FResult.SAFE.name:
            for i in range(3):
                self.code = self.programmer_agent.write_code_feedback_static(self.code, error_description, "")
                result, error_description = self.executor_static.execute_static_analysis_gpt(self.code)
                
                if result.name == FResult.SAFE.name:
                    static_analysis_status = f'fixed {i + 1}'
                    break 
                print('error feedback:' + error_description)
            if result.name != FResult.SAFE.name:
                static_analysis_status = 'fail: ' + error_description
        else:
            static_analysis_status = 'success'
        
        print(f"Programmer's Code after static analysis changes:\n{self.code}")
        # Step 3: Fuzzing agent generates initial test inputs
        test_inputs_list = []
        self.test_inputs = self.tester_fuzz_agent.generate_test_inputs()
        if (not self.test_inputs):
            #If no inputs generated for some reason, dynamic testing is not done
            task = {**problems[entry['ID']], "code": self.code, "fuzzing_inputs": test_inputs_list, "unit_test_status": "no unit tests", "static_analysis_status": static_analysis_status, "fuzzing_test_status": "No inputs created"}
            with open("results.json", 'a') as f:
                json.dump(task, f)
                f.write("\n")  # Write a new line after each JSON object
            return
        test_inputs_list.append(self.test_inputs)
        print(f"Initial Test Inputs:\n{self.test_inputs}")

        failed_inputs_fuzz = []
        fuzzing_test_status = None
        # Step 4: Execute and mutate in a loop for the given number of iterations
        for iteration in range(iterations):
            print(f"\nIteration {iteration + 1}")

            # Step 4a: Executor runs the code with current inputs
            try:
                result,passed,inputs,functionname = execute_fuzz(self.code,self.test_inputs, 3)
            except Exception as e:
                print("exception code", self.code)
                print(e)
                fuzzing_test_status = "error running function"
                break
            print(f"Execution Feedback:\n{result}")
            
            # If there's an error, flag the test as failed
            if not passed:
                if("No module named" in result):
                    fuzzing_test_status = "module missing: " + result
                    break
                elif("No root path can be found for the provided module 'builtins'" in result):
                    fuzzing_test_status = "prevent run by reliability_guard"
                    break
                else:
                    failed_inputs_fuzz.append({'inputs': inputs, 'result': result})
                    if len(failed_inputs_fuzz) > 10:
                        break
            
            mutator_agent = InputMutatorAgent(inputs, self.code,functionname)
            self.test_inputs = mutator_agent.mutate_inputs()
            test_inputs_list.append(self.test_inputs)
            print(f"Mutated Inputs:\n{self.test_inputs}")

        # Step 5: If errors were found in fuzzing, give feedback to coder to fix
        if len(failed_inputs_fuzz) != 0:
            problems[entry['ID']]['initial_failed_inputs'] = failed_inputs_fuzz[:5].copy()
            problems[entry['ID']]['code_before_fuzz_fix'] = self.code
            fuzzing_test_status = 'fail'
            # Give feedback to Coder up to 3 times
            for i in range(3):
                print(f"will try to fix code from fuzz try {i+1}")
                self.code = self.programmer_agent.write_code_feedback_fuzz(self.code, failed_inputs_fuzz[:5])
                print(f"code changed in fuzz {i+1}")
                print(self.code)
                new_failed_inputs = []
                for inputs in failed_inputs_fuzz:
                    try:
                        # run the code with the failing inputs to see if problem is fixed
                        result,passed,_inputs,_functionname = execute_fuzz(self.code,self.test_inputs, 3)
                    except Exception as e:
                        print("exception code", self.code)
                        print(e)
                        fuzzing_test_status = "error running function"
                        break
                    if not passed:
                        new_failed_inputs.append({'inputs': inputs, 'result': result})
                
                if len(new_failed_inputs) != 0:
                    failed_inputs_fuzz = new_failed_inputs
                    continue
                else:
                    fuzzing_test_status = f'fixed {i + 1}'
                    break
                
        else:
            if (fuzzing_test_status is None):
                fuzzing_test_status = 'success'    
                print(f"No errors encountered in {iterations} iterations.")
        
        # Step 6: Save the results in a JSON file
        if not os.path.exists("results.json"):
            with open("results.json", 'w') as f:
                pass
        
        #result includes code, fuzzing inputs used, static and fuzzing testing status
        task = {**problems[entry['ID']], "code": self.code, "fuzzing_inputs": test_inputs_list, "unit_test_status": "no unit tests", "static_analysis_status": static_analysis_status, "fuzzing_test_status": fuzzing_test_status}
        with open("results.json", 'a') as f:  # 'a' mode to append to the file
            json.dump(task, f)
            f.write("\n")  # Write a new line after each JSON object

        print(f"Tasks saved to results.json")

if __name__ == "__main__":
    
    #Security Eval dataset
    local_file_jsonl = "./dataset copy.jsonl"

    # Function to read the dataset from the jsonl file
    def read_dataset_jsonl(file_path):
        dataset = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                dataset.append(json.loads(line))
        return dataset

   # Load the dataset
    dataset = read_dataset_jsonl(local_file_jsonl)
    
    # =========================================================
    # --- NEW ROBUST RESUME LOGIC (REGEX) STARTS HERE ---
    # =========================================================
    # completed_task_ids = set()
    # if os.path.exists("results.json"):
    #     with open("results.json", 'r', encoding='utf-8') as f:
    #         content = f.read()
    #         # Extract all IDs regardless of JSON formatting
    #         matches = re.findall(r'"ID"\s*:\s*"([^"]+)"', content)
    #         for match in matches:
    #             completed_task_ids.add(match)
                
    # print(f"Found {len(completed_task_ids)} already completed tasks. Resuming...")
    # =========================================================
    # --- NEW ROBUST RESUME LOGIC (REGEX) ENDS HERE ---
    # =========================================================

    for entry in dataset:
        # 1. Extract the original prompt (handles both 'Prompt' and 'prompt' keys)
        original_prompt = entry.get('Prompt', entry.get('prompt', ''))
        task_id = entry.get('ID', 'Unknown')
        
        # =========================================================
        # --- SKIP LOGIC STARTS HERE ---
        # =========================================================
        # if task_id in completed_task_ids:
        #     print(f"Skipping {task_id} - already processed.")
        #     continue
        # =========================================================
        # --- SKIP LOGIC ENDS HERE ---
        # =========================================================
        
        # 2. RUN STAGE 0: Generate the Security Design Context
        print(f"\n{'='*50}")
        print(f"Executing Stage 0 for Task ID: {task_id}")
        print(f"{'='*50}")
        sdc_brief = generate_sdc_document(original_prompt)
        
        # 3. Compile the Enriched Prompt
        enriched_prompt = f"""
{sdc_brief}

---
### DOWNSTREAM IMPLEMENTATION SPECIFICATION
**FUNCTIONAL REQUIREMENT:**
{original_prompt}

**EXECUTION INSTRUCTION:** Generate a pristine Python implementation that fulfills the functional requirements while structurally eliminating the threat vectors mapped out in the Security Design Context above. Every identified CWE target must be thoroughly neutralized using the suggested defenses.
"""
        
        # 4. Swap the original prompt with your enriched one inside the dataset entry
        if 'Prompt' in entry:
            entry['Prompt'] = enriched_prompt
        else:
            entry['prompt'] = enriched_prompt
            
        # 5. Hand the enriched entry over to AutoSafeCoder's original workflow
        system = MultiAgentSystem(entry)
        system.run()

        # 6. RATE LIMIT PROTECTION TIMER
        print("\n[Timer] Sleeping for 20 seconds to prevent API rate limiting...")
        time.sleep(20)