# import cmd2
#
#
# class MyApp(cmd2.Cmd):
#     intro = 'Welcome to the DMK shell. Press Ctrl-D to exit.\n'
#     prompt = 'dmk> '
#
#     def do_foo(self, args):
#         """This docstring is the built-in help for the foo command."""
#         self.poutput(cmd2.style('foo bar baz', fg=cmd2.Fg.RED))
#
#     def do_hello_world(self, _: cmd2.Statement):
#         self.poutput('Hello World')
