from chkpkg import Package

if __name__ == "__main__":
    with Package() as pkg:
        pkg.run_shell_code('dmk --help')
        pkg.run_shell_code('dmk', expected_return_code=2)
        #pkg.run_shell_code('dmk --version')
        # todo problem with unicode: is it chkpkg or dmk problem?

    print("\nPackage is OK!")
