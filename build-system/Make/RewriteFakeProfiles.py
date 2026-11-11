#!/usr/bin/env python3
"""Retarget build-system/fake-codesigning profiles at another bundle id.

The committed profiles are App Store profiles for ph.telegra.Telegraph, signed by
the self-signed certificate in fake-codesigning/certs, and they expire. A sideload
build of Ghostgram needs the same certificate (team C67CF9S4VU, so codesign can
find the identity) with application identifiers under org.ghostgram.app, and a
date codesign will still accept. Sideloadly replaces the signature again.

    python3 build-system/Make/RewriteFakeProfiles.py \
        --bundle-id org.ghostgram.app \
        --destination /tmp/ghostgram-codesigning

--no-sign writes the rewritten plists without a CMS signature so the
string rewrite can be checked on a machine without the security tool.
"""

import argparse
import datetime
import os
import plistlib
import shutil
import subprocess
import sys

import GenerateProfiles

OLD_BUNDLE_ID = 'ph.telegra.Telegraph'
# The self-signed cert in fake-codesigning/certs is valid through 2030-10-29.
PROFILE_EXPIRATION = datetime.datetime(2030, 1, 1)


def rewrite_strings(value, old, new):
    if isinstance(value, str):
        return value.replace(old, new)
    if isinstance(value, list):
        return [rewrite_strings(item, old, new) for item in value]
    if isinstance(value, dict):
        return {key: rewrite_strings(item, old, new) for key, item in value.items()}
    return value


def load_profile(path):
    data = subprocess.check_output(
        ['openssl', 'smime', '-inform', 'der', '-verify', '-noverify', '-in', path],
        stderr=subprocess.DEVNULL,
    )
    return plistlib.loads(data)


def transform_profile(profile, old_bundle_id, new_bundle_id, certificate_der):
    profile = rewrite_strings(profile, old_bundle_id, new_bundle_id)
    profile['CreationDate'] = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    profile['ExpirationDate'] = PROFILE_EXPIRATION
    profile['TimeToLive'] = 3650
    profile.pop('DER-Encoded-Profile', None)
    profile['DeveloperCertificates'] = [certificate_der]
    return profile


def certificate_der(p12_path):
    # OpenSSL 3 needs -legacy for this p12 (RC2-40). LibreSSL on macOS does not
    # have -legacy and reads the same file without it.
    attempts = [
        ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:', '-nokeys', '-legacy'],
        ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:', '-nokeys'],
    ]
    pem = None
    errors = []
    for command in attempts:
        proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode == 0 and b'BEGIN CERTIFICATE' in proc.stdout:
            pem = proc.stdout
            break
        errors.append(proc.stderr.decode('utf-8', errors='replace'))
    if pem is None:
        sys.stderr.write('Could not read {}\n{}'.format(p12_path, '\n'.join(errors)))
        sys.exit(1)

    der = subprocess.check_output(['openssl', 'x509', '-outform', 'DER'], input=pem)
    subject = subprocess.check_output(
        ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'oneline,-esc_msb'],
        input=pem,
    ).decode('utf-8')
    if 'CN = ' not in subject:
        sys.stderr.write('No CN in certificate subject: {}\n'.format(subject))
        sys.exit(1)
    common_name = subject.split('CN = ', 1)[1].split(',')[0].strip()
    return der, common_name


def sign_profile(plist_path, destination, keychain_name, common_name):
    subprocess.check_call([
        'security', 'cms', '-S',
        '-k', keychain_name,
        '-N', common_name,
        '-i', plist_path,
        '-o', destination,
    ])


def main():
    parser = argparse.ArgumentParser(description='Rewrite fake provisioning profiles onto a bundle id')
    parser.add_argument('--source', default='build-system/fake-codesigning')
    parser.add_argument('--destination', required=True)
    parser.add_argument('--bundle-id', default='org.ghostgram.app')
    parser.add_argument('--old-bundle-id', default=OLD_BUNDLE_ID)
    parser.add_argument('--no-sign', action='store_true', help='Write unsigned plists (for checks off macOS)')
    args = parser.parse_args()

    source_profiles = os.path.join(args.source, 'profiles')
    source_certs = os.path.join(args.source, 'certs')
    p12_path = os.path.join(source_certs, 'SelfSigned.p12')
    if not os.path.isdir(source_profiles) or not os.path.isfile(p12_path):
        sys.stderr.write('Expected profiles and certs under {}\n'.format(args.source))
        sys.exit(1)

    dest_profiles = os.path.join(args.destination, 'profiles')
    dest_certs = os.path.join(args.destination, 'certs')
    if os.path.exists(args.destination):
        shutil.rmtree(args.destination)
    os.makedirs(dest_profiles)
    os.makedirs(dest_certs)
    for name in os.listdir(source_certs):
        path = os.path.join(source_certs, name)
        if os.path.isfile(path):
            shutil.copyfile(path, os.path.join(dest_certs, name))
    # Keep the committed p12. Re-exporting it with an empty password makes
    # `security import` report "MAC verification failed"; the original imports.

    der, common_name = certificate_der(p12_path)
    print('Signing identity: {}'.format(common_name))

    keychain_name = None
    if not args.no_sign:
        keychain_name = GenerateProfiles.setup_temp_keychain(p12_path, '')

    try:
        written = 0
        for name in sorted(os.listdir(source_profiles)):
            if not name.endswith('.mobileprovision'):
                continue
            profile = transform_profile(
                load_profile(os.path.join(source_profiles, name)),
                args.old_bundle_id,
                args.bundle_id,
                der,
            )
            identifier = profile['Entitlements']['application-identifier']
            destination = os.path.join(dest_profiles, name)
            plist_path = destination + '.plist'
            with open(plist_path, 'wb') as plist_file:
                plistlib.dump(profile, plist_file, fmt=plistlib.FMT_XML)
            if args.no_sign:
                os.replace(plist_path, destination)
            else:
                sign_profile(plist_path, destination, keychain_name, common_name)
                os.unlink(plist_path)
            print('{} -> {}'.format(name, identifier))
            written += 1
        if written == 0:
            sys.stderr.write('No profiles found in {}\n'.format(source_profiles))
            sys.exit(1)
    finally:
        if keychain_name is not None:
            GenerateProfiles.cleanup_temp_keychain(keychain_name)

    print('Wrote {} profiles to {}'.format(written, args.destination))


if __name__ == '__main__':
    main()
