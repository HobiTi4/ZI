import math
import random


class LCG:
    def __init__(self, m, a, c, x0):
        self.m = m
        self.a = a
        self.c = c
        self.state = x0

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


def calculate_period(m, a, c, x0):
    gen = LCG(m, a, c, x0)
    seen = {x0: 0}

    limit = min(m, 1_000_000)
    for i in range(1, limit + 1):
        val = gen.next()
        if val in seen:
            return i - seen[val]
        seen[val] = i

    return f"> {limit}"


def cesaro_test(gen_func, count):
    coprime = 0
    for _ in range(count):
        if math.gcd(gen_func(), gen_func()) == 1:
            coprime += 1
    if coprime == 0:
        return 0
    return math.sqrt(6 / (coprime / count))


def run_lab1_algorithm(m, a, c, x0, num_count):
    lcg = LCG(m, a, c, x0)
    generated_numbers = []

    with open("results.txt", "w") as f:
        for _ in range(num_count):
            val = lcg.next()
            generated_numbers.append(val)
            f.write(str(val) + "\n")

    period = calculate_period(m, a, c, x0)

    test_count = min(m, 10000)
    my_pi = cesaro_test(LCG(m, a, c, x0).next, test_count)
    sys_pi = cesaro_test(lambda: random.randint(0, m), test_count)

    return {
        'numbers': generated_numbers,
        'period': period,
        'my_pi': round(my_pi, 5),
        'sys_pi': round(sys_pi, 5),
        'real_pi': round(math.pi, 5)
    }