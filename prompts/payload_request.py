def request_payload_prompt():
    payload_request_prompt = "I have harness code as following:\n"

    pov_harness_impl_path = "nginx-cp/src/harnesses/pov_harness.cc"
    mail_harness_impl_path = "nginx-cp/src/harnesses/mail_request_harness.cc"
    smtp_harness_impl_path = "nginx-cp/src/harnesses/smtp_harness.cc"    
    project_yaml_path = "nginx-cp/project.yaml"

    harness_code = "\nThe followings are implementation of available harnesses.\n---pov_harness--\n"
    with open(pov_harness_impl_path, "r") as f:
        text = ""
        text = f.read()
        harness_code += text
    harness_code += "\n"

    harness_code += "---mail_request_harness--\n"
    with open(mail_harness_impl_path, "r") as f:
        text = ""
        text = f.read()
        harness_code += text
    harness_code += "\n"

    harness_code += "---smtp_harness--\n"
    with open(smtp_harness_impl_path, "r") as f:
        text = ""
        text = f.read()
        harness_code += text
    
    payload_request_prompt += harness_code
    payload_request_prompt += "\n"

    project_info = "The followings are available AddressSanitizers that could be triggered and test harnesses to test functionality.\n"
    with open(project_yaml_path, "r") as f:
        text = ""
        text = f.read()
        project_info += text
    project_info += "\n"

    payload_request_prompt += project_info
    payload_request_prompt += "If you need aditional information about some functions' implementation, please tell me in the following format: NEEDINFO func1 func2.... If you do not need, please generate an input in HTTP request format with localhost to tigger the vulnerability."
    return payload_request_prompt
