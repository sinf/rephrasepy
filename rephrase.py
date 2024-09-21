from argparse import ArgumentParser as ArgP, RawDescriptionHelpFormatter as RDHF
import subprocess
import itertools
import sys
import concurrent.futures
import textwrap

devnull=open('/dev/null','w')
GPG='/usr/bin/gpg'
CRYPTSETUP='/usr/bin/cryptsetup'

charsets={
    '?l': 'abcdefghijklmnopqrstuvwxyz',
    '?u': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    '?d': '0123456789',
    '?h': '0123456789abcdef',
    '?H': '0123456789ABCDEF',
    '?s': ' !"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~',
    '??': '?',
    #'?b': '0x00 - 0xff',
}
charsets['?a'] = ''.join(charsets[c] for c in ('?l','?u','?d','?s'))


class Command:
    def __init__(self, args, write_linefeed=1):
        self.args = args
        self.write_linefeed = write_linefeed
        self.param1 = ''
    def test(self, passphrase):
        inputs = passphrase
        if self.write_linefeed:
            inputs = passphrase + '\n'
        args = [arg.replace('%1', self.param1) for arg in self.args]
        sub = subprocess.run(args,
            input=inputs.encode(),
            stdout=devnull,
            stderr=devnull,
            #capture_output=True,
            env={},
            timeout=30)
        print(passphrase, ':', ' '.join(args), '->', sub.returncode)
        #print('stdout:', sub.stdout)
        #print('stderr:', sub.stderr)
        return sub.returncode == 0


class Passgen:
    def __init__(self):
        self.template = []
    
    def parse(self, template):
        skip_next=False
        i=0
        while i < len(template):
            c = template[i]
            if c == '?':
                if i+1 == len(template):
                    print('incomplete charset: ?')
                    sys.exit(1)
                c1 = template[i+1]
                if c1 == '-':
                    skip_next=True
                    i += 2
                    continue
                if c+c1 not in charsets:
                    print('unsupported charset:', c+c1)
                    sys.exit(1)
                new_set=charsets[c+c1]
                i += 2
            else:
                new_set=c
                i += 1
            if skip_next:
                skip_next=False
                new_set=list(new_set)+['']
            self.append(new_set)

    def append(self, thing):
        self.template.append(tuple(thing))

    def generate(self):
        return ( ''.join(x) for x in itertools.product(*self.template) )

profiles={
        #'gpg-key': Command( [ GPG, "--default-key", "%1", "--passphrase-fd", "0", "--batch", "--no-tty", "--dry-run", "--clear-sign", "/dev/null" ] ),
        'gpg-key': Command([
            GPG,
            "--default-key", "%1",
            "--passphrase-fd", "0",
            "--pinentry-mode", "loopback",
            "--batch",
            "--no-tty",
            "--dry-run",
            "--export-secret-keys",
            "-o", "/dev/null"
        ]),
        #'gpg-symmetric': Command( [ GPG, "--passphrase-fd", "0", "--batch", "--no-tty", "--decrypt", "%1" ] ),
        'luks': Command( [ CRYPTSETUP, "--test-passphrase", "--key-file", "/dev/fd/0", "open", "--type", "luks", "%1" ], write_linefeed=0 ),
}

def main():
    ap=ArgP(formatter_class=RDHF,
        description=textwrap.dedent(
        'Mask: mix of printable characters or hashcat masks. Available masks:\n\n' +
        '\n'.join(f'{k}: {v}' for k,v in charsets.items()) + '\n' +
        '?-: the next character is optional (it is removed for some guesses)\n'
        '?1: custom charset 1\n'
        '?2: custom charset 2\n'
        '?3: custom charset 3\n'
        '?4: custom charset 4\n'
    ))
    ap.add_argument('-m', '--mask', required=True, type=str)
    ap.add_argument('-p', '--profile', choices=profiles.keys(), required=True)
    ap.add_argument('-i', '--param1', type=str, required=True,
        help='Parameter passed to command. For gpg-key, it is private key name')
    ap.add_argument('-1', '--custom-charset1', type=str, default='')
    ap.add_argument('-2', '--custom-charset2', type=str, default='')
    ap.add_argument('-3', '--custom-charset3', type=str, default='')
    ap.add_argument('-4', '--custom-charset4', type=str, default='')
    ap.add_argument('-x', '--increment-mask', type=str,
        help='Once all attempts are exhausted, append this at the end once and restart. Default unset.')
    ap.add_argument('-c', '--increment-count', type=int, default=10,
        help='Number of increments done total. Default 10')
    ap.add_argument('-n', '--nproc', type=int, default=4)
    args=ap.parse_args()

    for i in range(1,5):
        charsets[f'?{i}'] = getattr(args, f'custom_charset{i}')

    print(args.profile)
    prof = profiles[args.profile]
    prof.param1 = args.param1
    gen = Passgen()
    gen.parse(args.mask)

    for k in range(1+args.increment_count):
        with concurrent.futures.ProcessPoolExecutor(args.nproc) as pool:
            for pw,ok in zip(gen.generate(), pool.map(prof.test, gen.generate(), chunksize=1)):
                if ok:
                    pool.shutdown(wait=False, cancel_futures=True)
                    print()
                    print('success:')
                    print(pw)
                    print()
                    return
        if not args.increment_mask:
            break
        gen.parse(args.increment_mask)

main()

