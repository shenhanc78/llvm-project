"""
Test that LLDB is separating C++ module types and debug information types
in the scratch AST.
"""

from lldbsuite.test.decorators import *
from lldbsuite.test.lldbtest import *
from lldbsuite.test import lldbutil


class TestCase(TestBase):
    @add_test_categories(["libc++"])
    @skipIf(compiler=no_match("clang"))
    @skipIf(macos_version=["<", "15.0"])
    @skipUnlessDarwin
    def test(self):
        """
        This test is creating ValueObjects with both C++ module and debug
        info types for std::vector<int>. We can't merge these types into
        the same AST, so for this test to pass LLDB should split the types
        up depending on whether they come from a module or not.
        """
        self.build()

        lldbutil.run_to_source_breakpoint(
            self, "// Set break point at this line.", lldb.SBFileSpec("main.cpp")
        )

        children = [
            ValueCheck(value="3"),
            ValueCheck(value="1"),
            ValueCheck(value="2"),
        ]

        if self.expectedCompiler(["clang"]) and self.expectedCompilerVersion(
            [">", "16.0"]
        ):
            vector_type = "std::vector<int>"
            dbg_vec_type = "std::vector<DbgInfoClass>"
            module_vector_type = "std::vector<int>"
        else:
            vector_type = "std::vector<int, std::allocator<int> >"
            dbg_vec_type = "std::vector<DbgInfoClass, std::allocator<DbgInfoClass> >"
            module_vector_type = "std::vector<int>"

        # First muddy the scratch AST with non-C++ module types.
        self.expect_expr("a", result_type=vector_type, result_children=children)
        self.expect_expr(
            "dbg_info_vec",
            result_type=dbg_vec_type,
            result_children=[
                ValueCheck(
                    type="DbgInfoClass",
                    children=[
                        ValueCheck(
                            name="ints",
                            type=vector_type,
                            children=[ValueCheck(value="1")],
                        )
                    ],
                )
            ],
        )

        # Enable the C++ module import and get the module vector type.
        self.runCmd("settings set target.import-std-module true")
        self.expect_expr("a", result_type=module_vector_type, result_children=children)

        # Test mixed debug info/module types
        self.expect_expr(
            "dbg_info_vec",
            result_type=dbg_vec_type,
            result_children=[
                ValueCheck(
                    type="DbgInfoClass",
                    children=[
                        ValueCheck(
                            name="ints",
                            type=module_vector_type,
                            children=[ValueCheck(value="1")],
                        )
                    ],
                )
            ],
        )

        # Turn off the C++ module import and use debug info types again.
        self.runCmd("settings set target.import-std-module false")
        self.expect_expr("a", result_type=vector_type, result_children=children)

        # Test the types that were previoiusly mixed debug info/module types.
        self.expect_expr(
            "dbg_info_vec",
            result_type=dbg_vec_type,
            result_children=[
                ValueCheck(
                    type="DbgInfoClass",
                    children=[
                        ValueCheck(
                            name="ints",
                            type=vector_type,
                            children=[ValueCheck(value="1")],
                        )
                    ],
                )
            ],
        )
