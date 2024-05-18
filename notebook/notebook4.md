\# python

import re

def filter_input(input_string):

    return re.sub('[^A-Za-z0-9]', '', input_string)

\# 示例

filtered_string = filter_input("Example!@#$%^&*()Input123")

print(filtered_string)  # 输出: ExampleInput123

