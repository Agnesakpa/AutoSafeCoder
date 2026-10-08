from stage0_design import generate_sdc_document

test_prompt = "Write a Python Flask endpoint that takes a user ID from the URL and queries the database to return their profile information."

# Run the agent
result = generate_sdc_document(test_prompt)

print("\n--- FINAL OUTPUT ---\n")
print(result)