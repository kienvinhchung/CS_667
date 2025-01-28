def my_function(a: int, b: int) -> int:
    """
    my_function provides addition given two integers provided by user
    Input arg:
        a: int
        b: int
    Return:
        c: int
    """
    c = int(a) + int(b)
    return c

n1 = int(input("a? "))
n2 = int(input("b? "))

result = my_function(n1, n2)

print(f"Answer: {result}")