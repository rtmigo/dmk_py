# import unittest
#
# from click.testing import CliRunner
#
# from codn import codn_cli
#
#
# class Test(unittest.TestCase):
#     def test(self):
#         runner = CliRunner()
#         result = runner.invoke(codn_cli,
#                                ['set', '-n', 'abc', '-v', 'The Value'])
#         self.assertEqual(result.exit_code, 0)
#         self.assertEqual(result.output, '')
#         result = runner.invoke(codn_cli,
#                                ['get', '-n', 'abc'])
#         self.assertEqual(result.exit_code, 0)
#         self.assertEqual(result.output, 'The Value\n')
#
#
# if __name__ == "__main__":
#     unittest.main()
