# Requirements for submission

### What is a class object?

- A class object is the object tha is created when a class is defined. A class is a blueprint, and an object is created based on the class.
- To define a class:

    ```python
    class className: 
        ''' docstring '''
        # start coding here
    ```

### What is a docstring?

- Doctring is short for documentation string. It is a string that can be a single or multiple lines that enclosed in triple single/double quotes. Often, doctring is located inside and on the first line of a class, object, etc.
- It is used to document a class, function, method, etc. to describe what the code does making it easier to understand and maintain.
- Examples: 

    ```python
    class className:
        """ documentation here """ 
        # start coding here
    ```

    ```python
    def functionName:
        ''' documentation here '''
        # start coding here
    ```

### How to define init class of a class object?

- It's a constructor to initialize newly created instances within `__init__` of the class.
- `self` refers to the instances being created.
- By default, `__init__` does not return anything.

    ```python
    class className: 
        """ docstring """

        def __init__(self):
            """ doctring """
            # start coding here
    ```

### What is a method?

- It's a function that is defined inside a class to perform operation son instances of that class.
- In another word, methods are basically functions inside a class.
- Method takes self as the first parameter, which refers to the instances.

    ```python
    class className:
        ''' docstring '''

        def __init__(self):
            ''' docstring '''
            # start coding here

        def methodOne(self):
            ''' docstring '''
            # start coding here
    ```

### How do you let functions fail gracefully?

- Funtion fails gracefully means we handle errors without crashing the entire function/program.

- The easiest and most popular way is by using `try-except`

    ```python
    def divideFunction(a, b):
        ''' Return result of a divided by b '''
        try:
            return a / b
        except ZeroDivisionError:
            return "Undefined! Cannot divide by zero."
    ```

### What's a standard practice of a return statement?

- If a function is expected to produce an output, we should use `return` instead of `print`.

- A `return` statement exits a function and returns a value to the caller.

    ```python
    # Correct:

    def add(a, b):
        return a + b

    result = add(2, 3)
    print(result)
    ```

    ```python
    # Correct:

    def get_user():
        """Returns user details in JSON format"""
        user_data = {"name": "John", "age": 30, "city": "New York"}
        return json.dumps(user_data)  # Convert dictionary to JSON string

    print(get_user())
    ```

    ```python
    # Incorrect:
    
    def add(a, b):
        print(a + b)

    add(2, 3)
    ```