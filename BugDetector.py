import ast
import re
import os

text_file = open(
    "C:/Users/For_Support/OneDrive/Desktop/loop.txt", "r")

code = text_file.read()


def detect_directory_traversal(code):
    pattern = r'\.\./|\.\./\.\./'

    matches = re.findall(pattern, code)

    if matches:
        for match in matches:
            print(f"Directory traversal detected: {match}")


def detect_unused_variables(code):
    tree = ast.parse(code)
    unused_variables = []

    class UnusedVariableVisitor(ast.NodeVisitor):
        def __init__(self):
            self.variables = set()
            self.unused_variables = []

        def visit_Assign(self, node):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.variables.add(target.id)

            self.generic_visit(node)

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in self.variables:
                self.variables.remove(node.id)

            self.generic_visit(node)

    visitor = UnusedVariableVisitor()
    visitor.visit(tree)

    for variable in visitor.variables:
        unused_variables.append(
            f"Variable '{variable}' is defined but never used.")

    return unused_variables


def detect_xss(code):

    xss_regex = re.compile(r".*({{|}}|<\s*script\b|on\w+\s*=)", re.IGNORECASE)

    xss = []
    for i, line in enumerate(code.split('\n')):
        if re.match(xss_regex, line):
            msg = f"Potential XSS vulnerability: {line.strip()}"
            xss.append((i+1, msg))

    return xss


def detect_division_by_zero(code):

    tree = ast.parse(code)

    class DivByZeroVisitor(ast.NodeVisitor):
        def visit_BinOp(self, node):
            if isinstance(node.op, ast.Div) or isinstance(node.op, ast.FloorDiv):
                if isinstance(node.right, ast.Num) and node.right.n == 0:
                    line, col = node.right.lineno, node.right.col_offset
                    div_by_zero_locs.append((line, col))
                elif isinstance(node.right, ast.Name) and node.right.id == '0':
                    line, col = node.right.lineno, node.right.col_offset
                    div_by_zero_locs.append((line, col))
            self.generic_visit(node)

    div_by_zero_locs = []
    visitor = DivByZeroVisitor()
    visitor.visit(tree)

    return div_by_zero_locs


def detect_bugs(code):
    tree = ast.parse(code)

    bugs = []

    # Extract strings
    strings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Str):
            strings.append(node.s)
    # check if any of the strings are directories
    for string in strings:
        if os.path.isdir(os.path.dirname(string)) and not os.path.exists(string):
            bugs.append(f'Directory does not exist: {string}')

    # Check for syntax errors in the code
    try:
        compile(code, '<string>', 'exec')
    except SyntaxError as e:
        bugs.append(str(e))

    # Check for infinite loops
    def check_loops(node):
        if isinstance(node, ast.While):
            if not any(isinstance(child, ast.Break) or isinstance(child, ast.Return) or isinstance(child, ast.Raise) for child in ast.walk(node)):
                bugs.append(
                    'Infinite loop warning: loop condition always evaluates to True')

        for child_node in ast.iter_child_nodes(node):
            check_loops(child_node)

    check_loops(tree)

    # Check for type errors in the code
    def check_type(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            if isinstance(node.left, ast.Str) and isinstance(node.right, ast.Str):
                pass  # String concatenation
            elif isinstance(node.left, ast.Str) and not isinstance(node.right, ast.Str):
                bugs.append(
                    f'Type error on line {node.lineno}: cannot concatenate string and non-string')
            elif not isinstance(node.left, ast.Str) and isinstance(node.right, ast.Str):
                bugs.append(
                    f'Type error on line {node.lineno}: cannot concatenate non-string and string')

        for child_node in ast.iter_child_nodes(node):
            check_type(child_node)

    check_type(tree)

    # Check for unused variables in the code
    unused_variables = detect_unused_variables(code)
    if unused_variables:
        bugs.append(f'Unused variables: {", ".join(unused_variables)}')

    div_by_zero = detect_division_by_zero(code)
    for line, col in div_by_zero:
        bugs.append((line, "Division by zero"))

    return bugs


bugs = detect_bugs(code)
print(bugs)

detect_directory_traversal(code)

# for line, msg in bugs:
#     print(f"Line {line}: {msg}")

# xss = detect_xss(code)
# for line, msg in xss:
#     print(f"Line {line}: {msg}")
