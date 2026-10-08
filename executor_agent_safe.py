import json
from typing import Optional, Callable, Dict
import ast
import contextlib
import faulthandler
import io
import os
import multiprocessing
import platform
import signal
import tempfile
from enum import Enum

class FResult(Enum):
    SAFE = 1  # validation returns okay
    FAILURE = 2  # validation contains error (something wrong with validation)
    ERROR = 3  # validation returns a potential error (look into)
    LLM_WEAKNESS = (
        4  # the generated input is ill-formed due to the weakness of the language model
    )
    TIMED_OUT = 10  # timed out, can be okay in certain targets

def remove_json_prefix(input_str):
    # Check if the input string starts with "json\n"
    if input_str.startswith("json\n"):
        # Remove the prefix and return the remaining string
        return input_str[len("json\n"):]
    return input_str

def execute_fuzz(completion: str, input_json, timeout: float,
                      completion_id: Optional[int] = None) -> Dict:
    """
    Evaluates the functional correctness of a completion by running the test
    suite provided in the problem. 

    :param completion_id: an optional completion ID so we can match
        the results later even if execution finishes asynchronously.
    """

    def get_exec_code(code, inputs_json):
        if isinstance(inputs_json,str):
            # Parse the inputs string from JSON
            inputs = remove_json_prefix(inputs_json)
            inputs = json.loads(inputs)
        else: 
            inputs = inputs_json
        # Prepare the Python script content
        func_name = [line.split('(')[0].replace('def ', '').strip() for line in code.splitlines() if line.strip().startswith('def')][0]
        script_content = f"""
import json

{code}
    
def main():
    inputs = {inputs}

    try:
        result = {func_name}(**inputs)
        print(json.dumps({{"status": "success", "result": result}}))
    except Exception as e:
        print(json.dumps({{"status": "error", "error": str(e)}}))
        

if __name__ == "__main__":
    main()
    """
        return script_content, inputs, func_name


    def unsafe_execute():
        with create_tempdir():

            # These system calls are needed when cleaning up tempdir.
            import os
            import shutil
            rmtree = shutil.rmtree
            rmdir = os.rmdir
            chdir = os.chdir

            # Disable functionalities that can make destructive changes to the test.
            reliability_guard(code_string=completion)
            
            code_to_run, inputs, func_name = get_exec_code(completion, input_json)
            inputs_list.append(inputs)
            func_names.append(func_name)
            # Construct the check program and run it.
            check_program = (
                code_to_run + "\n"
            )

            try:
                exec_globals = {}
                with swallow_io():
                    with time_limit(timeout):
# WARNING
# This program exists to execute untrusted model-generated code. Although
# it is highly unlikely that model-generated code will do something overtly
# malicious in response to this test suite, model-generated code may act
# destructively due to a lack of model capability or alignment.
# Users are strongly encouraged to sandbox this evaluation suite so that it 
# does not perform destructive actions on their host or network. For more 
# information on how OpenAI sandboxes its code, see the accompanying paper.
# Once you have read this disclaimer and taken appropriate precautions, 
# uncomment the following line and proceed at your own risk:
                        exec(check_program, exec_globals)
                result.append("passed")
            except TimeoutException:
                result.append("timed out")
            except AssertionError as e:
                    result.append(f"failed: AssertionError {e}")
            except BaseException as e:
                result.append(f"failed: {e}")

            # Needed for cleaning up.
            shutil.rmtree = rmtree
            os.rmdir = rmdir
            os.chdir = chdir

    manager = multiprocessing.Manager()
    result = manager.list()
    inputs_list = manager.list()
    func_names = manager.list()

    p = multiprocessing.Process(target=unsafe_execute)
    p.start()
    p.join(timeout=timeout + 1)
    if p.is_alive():
        p.kill()

    if not result:
        result.append("timed out")

    return result[0], result[0] == 'passed', inputs_list[0], func_names[0]


@contextlib.contextmanager
def time_limit(seconds: float):
    def signal_handler(signum, frame):
        raise TimeoutException("Timed out!")
    signal.setitimer(signal.ITIMER_REAL, seconds)
    signal.signal(signal.SIGALRM, signal_handler)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


@contextlib.contextmanager
def swallow_io():
    stream = WriteOnlyStringIO()
    with contextlib.redirect_stdout(stream):
        with contextlib.redirect_stderr(stream):
            with redirect_stdin(stream):
                yield


@contextlib.contextmanager
def create_tempdir():
    with tempfile.TemporaryDirectory() as dirname:
        with chdir(dirname):
            yield dirname


class TimeoutException(Exception):
    pass


class WriteOnlyStringIO(io.StringIO):
    """ StringIO that throws an exception when it's read from """

    def read(self, *args, **kwargs):
        raise IOError

    def readline(self, *args, **kwargs):
        raise IOError

    def readlines(self, *args, **kwargs):
        raise IOError

    def readable(self, *args, **kwargs):
        """ Returns True if the IO object can be read. """
        return False


class redirect_stdin(contextlib._RedirectStream):  # type: ignore
    _stream = 'stdin'


@contextlib.contextmanager
def chdir(root):
    if root == ".":
        yield
        return
    cwd = os.getcwd()
    os.chdir(root)
    try:
        yield
    except BaseException as exc:
        raise exc
    finally:
        os.chdir(cwd)


def reliability_guard(maximum_memory_bytes: Optional[int] = None, code_string=""):
    """
    FIXED GUARD: The previous guard was sabotaging Python's 'builtins' and 'sys.modules', 
    which caused Flask and other libraries to completely crash during fuzzing.
    This new version only blocks actual system shell executions (os.system, subprocess)
    and allows standard Python logic to execute safely inside the temporary directory.
    """
    import os
    import subprocess

    # Block highly destructive shell executions
    os.system = None
    subprocess.Popen = None  # type: ignore

    # Set memory limits to prevent the LLM from creating infinite loops that crash your RAM
    if maximum_memory_bytes is not None:
        import resource
        try:
            resource.setrlimit(resource.RLIMIT_AS, (maximum_memory_bytes, maximum_memory_bytes))
            resource.setrlimit(resource.RLIMIT_DATA, (maximum_memory_bytes, maximum_memory_bytes))
            if not platform.uname().system == 'Darwin':
                resource.setrlimit(resource.RLIMIT_STACK, (maximum_memory_bytes, maximum_memory_bytes))
        except Exception:
            pass