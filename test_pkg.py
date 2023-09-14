from chkpkg import Package

if __name__ == "__main__":
    with Package() as pkg:
        pkg.run_shell_code('dmk --help')
        # pkg.run_shell_code('dmk', expected_return_code=2)
        pkg.run_shell_code('dmk --version')
        # todo problem with unicode: is it chkpkg or dmk problem?
        pkg.run_python_code("from dmk import DmkFile, get_text, set_text, "
                            "get_file, set_file")

    print("\nPackage is OK!")
