import os
import sys
import argparse

from BuildEnvironment import run_executable_with_output

def import_certificates(certificatesPath):
    if not os.path.exists(certificatesPath):
        print('{} does not exist'.format(certificatesPath))
        sys.exit(1)

    keychain_name = 'temp.keychain'
    keychain_password = 'secret'

    existing_keychains = run_executable_with_output('security', arguments=['list-keychains'], check_result=True)
    if keychain_name in existing_keychains:
        # The keychain name is required. Without it `security` fails with
        # "SecKeychainDelete: The specified keychain is not a valid keychain file",
        # which only happens on a second build inside one VM -- unreachable while every
        # build got a fresh ephemeral VM, and hit on every reuse of a persistent one.
        run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=True)

    run_executable_with_output('security', arguments=[
        'create-keychain',
        '-p',
        keychain_password,
        keychain_name
    ], check_result=True)

    existing_keychains = run_executable_with_output('security', arguments=['list-keychains', '-d', 'user'])
    # list-keychains prints one quoted path per line. Pass each path as its own
    # argument; the previous code dropped the quote-stripping result and handed
    # the whole block to -s as a single argv, which a fresh CI keychain rejects.
    existing_paths = []
    for line in existing_keychains.splitlines():
        path = line.strip().strip('"')
        if path and path not in existing_paths and not path.endswith(keychain_name):
            existing_paths.append(path)

    run_executable_with_output('security', arguments=[
        'list-keychains',
        '-d',
        'user',
        '-s',
        keychain_name,
    ] + existing_paths, check_result=True)

    run_executable_with_output('security', arguments=['default-keychain', '-s', keychain_name], check_result=True)
    run_executable_with_output('security', arguments=['set-keychain-settings', keychain_name])
    run_executable_with_output('security', arguments=['unlock-keychain', '-p', keychain_password, keychain_name])

    for file_name in os.listdir(certificatesPath):
        file_path = certificatesPath + '/' + file_name
        if file_path.endswith('.p12') or file_path.endswith('.cer'):
            run_executable_with_output('security', arguments=[
                'import',
                file_path,
                '-k',
                keychain_name,
                '-P',
                '',
                '-T',
                '/usr/bin/codesign',
                '-T',
                '/usr/bin/security'
            ], check_result=False)

    run_executable_with_output('security', arguments=[
        'import',
        'build-system/AppleWWDRCAG3.cer',
        '-k',
        keychain_name,
        '-P',
        '',
        '-T',
        '/usr/bin/codesign',
        '-T',
        '/usr/bin/security'
    ], check_result=False)

    # codesign: is required on a headless runner. Without it the key is in the
    # keychain but codesign exits "User interaction is not allowed".
    run_executable_with_output('security', arguments=[
        'set-key-partition-list',
        '-S',
        'apple-tool:,apple:,codesign:',
        '-s',
        '-k',
        keychain_password,
        keychain_name
    ], check_result=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='build')

    parser.add_argument(
        '--path',
        required=True,
        help='Path to certificates.'
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    import_certificates(args.path)
