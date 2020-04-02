import sys
import getopt


def main(argv):
    client = ''
    server = ''
    password = 'jkh'
    opts, args = getopt.getopt(argv, 'c:s:p:', ['client', 'server', 'pw'])
    for opt, arg in opts:
        if opt in ('-c', '--client'):
            client = arg
        elif opt in ('-s', '--server'):
            server = arg
        elif opt in ('-p', '--pw'):
            password = arg
    print('client port:', client)
    print('server port: ', server)
    print(password.encode('ascii'))


if __name__ == '__main__':
    main(sys.argv[1:])
    print(sys.argv)
