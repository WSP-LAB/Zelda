def clear_line(n=1):
    print('\033[?25l', end="")
    print('\033[%dA\033[3K' % n, end='')
    """
    LINE_UP = '\033[1A'
    LINE_CLEAR = '\x1b[2K'
    for i in range(n):
        print(LINE_UP, end=LINE_CLEAR)
    """
