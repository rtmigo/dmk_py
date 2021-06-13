from chkpkg import Package

if __name__ == "__main__":
    with Package() as pkg:
        pkg.run_shell_code('codn --help')
        pkg.run_shell_code('codn --version')

    print("\nPackage is OK!")
