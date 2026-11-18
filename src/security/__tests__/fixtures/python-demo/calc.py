"""A tiny calculator. Deliberately vulnerable: evaluates the expression
as Python (CWE-95)."""


def calculate(expression):
    result = eval(expression)
    return result
