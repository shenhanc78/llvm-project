//===-- clang-doc/HTMLGeneratorTest.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "ClangDocTest.h"
#include "Generators.h"
#include "Representation.h"
#include "clang/Basic/Version.h"
#include "gtest/gtest.h"

namespace clang {
namespace doc {

static const std::string ClangDocVersion =
    clang::getClangToolFullVersion("clang-doc");

static std::unique_ptr<Generator> getHTMLGenerator() {
  auto G = doc::findGeneratorByName("html");
  if (!G)
    return nullptr;
  return std::move(G.get());
}

static ClangDocContext
getClangDocContext(std::vector<std::string> UserStylesheets = {},
                   StringRef RepositoryUrl = "",
                   StringRef RepositoryLinePrefix = "", StringRef Base = "") {
  ClangDocContext CDCtx{
      {},   "test-project", {}, {}, {}, RepositoryUrl, RepositoryLinePrefix,
      Base, UserStylesheets};
  CDCtx.UserStylesheets.insert(
      CDCtx.UserStylesheets.begin(),
      "../share/clang/clang-doc-default-stylesheet.css");
  CDCtx.JsScripts.emplace_back("index.js");
  return CDCtx;
}

TEST(HTMLGeneratorTest, emitNamespaceHTML) {
  NamespaceInfo I;
  I.Name = "Namespace";
  I.Namespace.emplace_back(EmptySID, "A", InfoType::IT_namespace);

  I.Children.Namespaces.emplace_back(EmptySID, "ChildNamespace",
                                     InfoType::IT_namespace,
                                     "Namespace::ChildNamespace", "Namespace");
  I.Children.Records.emplace_back(EmptySID, "ChildStruct", InfoType::IT_record,
                                  "Namespace::ChildStruct", "Namespace");
  I.Children.Functions.emplace_back();
  I.Children.Functions.back().Access = AccessSpecifier::AS_none;
  I.Children.Functions.back().Name = "OneFunction";
  I.Children.Enums.emplace_back();
  I.Children.Enums.back().Name = "OneEnum";

  auto G = getHTMLGenerator();
  assert(G);
  std::string Buffer;
  llvm::raw_string_ostream Actual(Buffer);
  ClangDocContext CDCtx = getClangDocContext({"user-provided-stylesheet.css"});
  auto Err = G->generateDocForInfo(&I, Actual, CDCtx);
  assert(!Err);
  std::string Expected = R"raw(<!DOCTYPE html>
<meta charset="utf-8"/>
<title>namespace Namespace</title>
<link rel="stylesheet" href="../clang-doc-default-stylesheet.css"/>
<link rel="stylesheet" href="../user-provided-stylesheet.css"/>
<script src="../index_json.js"></script>
<script src="../index.js"></script>
<header id="project-title">test-project</header>
<main>
  <div id="sidebar-left" path="Namespace" class="col-xs-6 col-sm-3 col-md-2 sidebar sidebar-offcanvas-left"></div>
  <div id="main-content" class="col-xs-12 col-sm-9 col-md-8 main-content">
    <h1>namespace Namespace</h1>
    <h2 id="Namespaces">Namespaces</h2>
    <ul>
      <li>
        <a href="ChildNamespace/index.html">ChildNamespace</a>
      </li>
    </ul>
    <h2 id="Records">Records</h2>
    <ul>
      <li>
        <a href="ChildStruct.html">ChildStruct</a>
      </li>
    </ul>
    <h2 id="Functions">Functions</h2>
    <div>
      <h3 id="0000000000000000000000000000000000000000">OneFunction</h3>
      <p>OneFunction()</p>
    </div>
    <h2 id="Enums">Enums</h2>
    <div>
      <table id="0000000000000000000000000000000000000000">
        <thead>
          <tr>
            <th colspan="2">enum OneEnum</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>
  <div id="sidebar-right" class="col-xs-6 col-sm-6 col-md-2 sidebar sidebar-offcanvas-right">
    <ol>
      <li>
        <span>
          <a href="#Namespaces">Namespaces</a>
        </span>
      </li>
      <li>
        <span>
          <a href="#Records">Records</a>
        </span>
      </li>
      <li>
        <span>
          <a href="#Functions">Functions</a>
        </span>
        <ul>
          <li>
            <span>
              <a href="#0000000000000000000000000000000000000000">OneFunction</a>
            </span>
          </li>
        </ul>
      </li>
      <li>
        <span>
          <a href="#Enums">Enums</a>
        </span>
        <ul>
          <li>
            <span>
              <a href="#0000000000000000000000000000000000000000">OneEnum</a>
            </span>
          </li>
        </ul>
      </li>
    </ol>
  </div>
</main>
<footer>
  <span class="no-break">)raw" +
                         ClangDocVersion + R"raw(</span>
</footer>
)raw";

  EXPECT_EQ(Expected, Actual.str());
}

TEST(HTMLGeneratorTest, emitRecordHTML) {
  RecordInfo I;
  I.Name = "r";
  I.Path = "X/Y/Z";
  I.Namespace.emplace_back(EmptySID, "A", InfoType::IT_namespace);

  I.DefLoc = Location(10, 10, "dir/test.cpp", true);
  I.Loc.emplace_back(12, 12, "test.cpp");

  SmallString<16> PathTo;
  llvm::sys::path::native("path/to", PathTo);
  I.Members.emplace_back(TypeInfo("int"), "X", AccessSpecifier::AS_private);
  I.TagType = TagTypeKind::Class;
  I.Parents.emplace_back(EmptySID, "F", InfoType::IT_record, "F", PathTo);
  I.VirtualParents.emplace_back(EmptySID, "G", InfoType::IT_record);

  I.Children.Records.emplace_back(EmptySID, "ChildStruct", InfoType::IT_record,
                                  "X::Y::Z::r::ChildStruct", "X/Y/Z/r");
  I.Children.Functions.emplace_back();
  I.Children.Functions.back().Name = "OneFunction";
  I.Children.Enums.emplace_back();
  I.Children.Enums.back().Name = "OneEnum";

  auto G = getHTMLGenerator();
  assert(G);
  std::string Buffer;
  llvm::raw_string_ostream Actual(Buffer);
  ClangDocContext CDCtx = getClangDocContext({}, "http://www.repository.com");
  auto Err = G->generateDocForInfo(&I, Actual, CDCtx);
  assert(!Err);
  std::string Expected = R"raw(<!DOCTYPE html>
<meta charset="utf-8"/>
<title>class r</title>
<link rel="stylesheet" href="../../../clang-doc-default-stylesheet.css"/>
<script src="../../../index_json.js"></script>
<script src="../../../index.js"></script>
<header id="project-title">test-project</header>
<main>
  <div id="sidebar-left" path="X/Y/Z" class="col-xs-6 col-sm-3 col-md-2 sidebar sidebar-offcanvas-left"></div>
  <div id="main-content" class="col-xs-12 col-sm-9 col-md-8 main-content">
    <h1>class r</h1>
    <p>
      Defined at line 
      <a href="http://www.repository.com/dir/test.cpp#10">10</a>
       of file 
      <a href="http://www.repository.com/dir/test.cpp">test.cpp</a>
    </p>
    <p>
      Inherits from 
      <a href="../../../path/to/F.html">F</a>
      , G
    </p>
    <h2 id="Members">Members</h2>
    <ul>
      <li>
        <div>private int X</div>
      </li>
    </ul>
    <h2 id="Records">Records</h2>
    <ul>
      <li>
        <a href="../../../X/Y/Z/r/ChildStruct.html">ChildStruct</a>
      </li>
    </ul>
    <h2 id="Functions">Functions</h2>
    <div>
      <h3 id="0000000000000000000000000000000000000000">OneFunction</h3>
      <p>public OneFunction()</p>
    </div>
    <h2 id="Enums">Enums</h2>
    <div>
      <table id="0000000000000000000000000000000000000000">
        <thead>
          <tr>
            <th colspan="2">enum OneEnum</th>
          </tr>
        </thead>
      </table>
    </div>
  </div>
  <div id="sidebar-right" class="col-xs-6 col-sm-6 col-md-2 sidebar sidebar-offcanvas-right">
    <ol>
      <li>
        <span>
          <a href="#Members">Members</a>
        </span>
      </li>
      <li>
        <span>
          <a href="#Records">Records</a>
        </span>
      </li>
      <li>
        <span>
          <a href="#Functions">Functions</a>
        </span>
        <ul>
          <li>
            <span>
              <a href="#0000000000000000000000000000000000000000">OneFunction</a>
            </span>
          </li>
        </ul>
      </li>
      <li>
        <span>
          <a href="#Enums">Enums</a>
        </span>
        <ul>
          <li>
            <span>
              <a href="#0000000000000000000000000000000000000000">OneEnum</a>
            </span>
          </li>
        </ul>
      </li>
    </ol>
  </div>
</main>
<footer>
  <span class="no-break">)raw" +
                         ClangDocVersion + R"raw(</span>
</footer>
)raw";

  EXPECT_EQ(Expected, Actual.str());
}

TEST(HTMLGeneratorTest, emitFunctionHTML) {
  FunctionInfo I;
  I.Name = "f";
  I.Namespace.emplace_back(EmptySID, "A", InfoType::IT_namespace);

  I.DefLoc = Location(10, 10, "dir/test.cpp", true);
  I.Loc.emplace_back(12, 12, "test.cpp");

  I.Access = AccessSpecifier::AS_none;

  SmallString<16> PathTo;
  llvm::sys::path::native("path/to", PathTo);
  I.ReturnType = TypeInfo(
      Reference(EmptySID, "float", InfoType::IT_default, "float", PathTo));
  I.Params.emplace_back(TypeInfo("int", PathTo), "P");
  I.IsMethod = true;
  I.Parent = Reference(EmptySID, "Parent", InfoType::IT_record);

  auto G = getHTMLGenerator();
  assert(G);
  std::string Buffer;
  llvm::raw_string_ostream Actual(Buffer);
  ClangDocContext CDCtx = getClangDocContext({}, "https://www.repository.com");
  auto Err = G->generateDocForInfo(&I, Actual, CDCtx);
  assert(!Err);
  std::string Expected = R"raw(<!DOCTYPE html>
<meta charset="utf-8"/>
<title></title>
<link rel="stylesheet" href="clang-doc-default-stylesheet.css"/>
<script src="index_json.js"></script>
<script src="index.js"></script>
<header id="project-title">test-project</header>
<main>
  <div id="sidebar-left" path="" class="col-xs-6 col-sm-3 col-md-2 sidebar sidebar-offcanvas-left"></div>
  <div id="main-content" class="col-xs-12 col-sm-9 col-md-8 main-content">
    <h3 id="0000000000000000000000000000000000000000">f</h3>
    <p>
      <a href="path/to/float.html">float</a>
       f(
      <a href="path/to/int.html">int</a>
       P)
    </p>
    <p>
      Defined at line 
      <a href="https://www.repository.com/dir/test.cpp#10">10</a>
       of file 
      <a href="https://www.repository.com/dir/test.cpp">test.cpp</a>
    </p>
  </div>
  <div id="sidebar-right" class="col-xs-6 col-sm-6 col-md-2 sidebar sidebar-offcanvas-right"></div>
</main>
<footer>
  <span class="no-break">)raw" +
                         ClangDocVersion + R"raw(</span>
</footer>
)raw";

  EXPECT_EQ(Expected, Actual.str());
}

TEST(HTMLGeneratorTest, emitEnumHTML) {
  EnumInfo I;
  I.Name = "e";
  I.Namespace.emplace_back(EmptySID, "A", InfoType::IT_namespace);

  I.DefLoc = Location(10, 10, "test.cpp", true);
  I.Loc.emplace_back(12, 12, "test.cpp");

  I.Members.emplace_back("X");
  I.Scoped = true;

  auto G = getHTMLGenerator();
  assert(G);
  std::string Buffer;
  llvm::raw_string_ostream Actual(Buffer);
  ClangDocContext CDCtx = getClangDocContext({}, "www.repository.com");
  auto Err = G->generateDocForInfo(&I, Actual, CDCtx);
  assert(!Err);
  std::string Expected = R"raw(<!DOCTYPE html>
<meta charset="utf-8"/>
<title></title>
<link rel="stylesheet" href="clang-doc-default-stylesheet.css"/>
<script src="index_json.js"></script>
<script src="index.js"></script>
<header id="project-title">test-project</header>
<main>
  <div id="sidebar-left" path="" class="col-xs-6 col-sm-3 col-md-2 sidebar sidebar-offcanvas-left"></div>
  <div id="main-content" class="col-xs-12 col-sm-9 col-md-8 main-content">
    <table id="0000000000000000000000000000000000000000">
      <thead>
        <tr>
          <th colspan="2">enum class e</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>X</td>
          <td>0</td>
        </tr>
      </tbody>
    </table>
    <p>
      Defined at line 
      <a href="https://www.repository.com/test.cpp#10">10</a>
       of file 
      <a href="https://www.repository.com/test.cpp">test.cpp</a>
    </p>
  </div>
  <div id="sidebar-right" class="col-xs-6 col-sm-6 col-md-2 sidebar sidebar-offcanvas-right"></div>
</main>
<footer>
  <span class="no-break">)raw" +
                         ClangDocVersion + R"raw(</span>
</footer>
)raw";

  EXPECT_EQ(Expected, Actual.str());
}

TEST(HTMLGeneratorTest, emitCommentHTML) {
  FunctionInfo I;
  I.Name = "f";
  I.DefLoc = Location(10, 10, "test.cpp", true);
  I.ReturnType = TypeInfo("void");
  I.Params.emplace_back(TypeInfo("int"), "I");
  I.Params.emplace_back(TypeInfo("int"), "J");
  I.Access = AccessSpecifier::AS_none;

  CommentInfo Top;
  Top.Kind = CommentKind::CK_FullComment;

  Top.Children.emplace_back(std::make_unique<CommentInfo>());
  CommentInfo *BlankLine = Top.Children.back().get();
  BlankLine->Kind = CommentKind::CK_ParagraphComment;
  BlankLine->Children.emplace_back(std::make_unique<CommentInfo>());
  BlankLine->Children.back()->Kind = CommentKind::CK_TextComment;

  Top.Children.emplace_back(std::make_unique<CommentInfo>());
  CommentInfo *Brief = Top.Children.back().get();
  Brief->Kind = CommentKind::CK_ParagraphComment;
  Brief->Children.emplace_back(std::make_unique<CommentInfo>());
  Brief->Children.back()->Kind = CommentKind::CK_TextComment;
  Brief->Children.back()->Name = "ParagraphComment";
  Brief->Children.back()->Text = " Brief description.";

  Top.Children.emplace_back(std::make_unique<CommentInfo>());
  CommentInfo *Extended = Top.Children.back().get();
  Extended->Kind = CommentKind::CK_ParagraphComment;
  Extended->Children.emplace_back(std::make_unique<CommentInfo>());
  Extended->Children.back()->Kind = CommentKind::CK_TextComment;
  Extended->Children.back()->Text = " Extended description that";
  Extended->Children.emplace_back(std::make_unique<CommentInfo>());
  Extended->Children.back()->Kind = CommentKind::CK_TextComment;
  Extended->Children.back()->Text = " continues onto the next line.";

  Top.Children.emplace_back(std::make_unique<CommentInfo>());
  CommentInfo *Entities = Top.Children.back().get();
  Entities->Kind = CommentKind::CK_ParagraphComment;
  Entities->Children.emplace_back(std::make_unique<CommentInfo>());
  Entities->Children.back()->Kind = CommentKind::CK_TextComment;
  Entities->Children.back()->Name = "ParagraphComment";
  Entities->Children.back()->Text =
      " Comment with html entities: &, <, >, \", \'.";

  I.Description.emplace_back(std::move(Top));

  auto G = getHTMLGenerator();
  assert(G);
  std::string Buffer;
  llvm::raw_string_ostream Actual(Buffer);
  ClangDocContext CDCtx = getClangDocContext();
  auto Err = G->generateDocForInfo(&I, Actual, CDCtx);
  assert(!Err);
  std::string Expected = R"raw(<!DOCTYPE html>
<meta charset="utf-8"/>
<title></title>
<link rel="stylesheet" href="clang-doc-default-stylesheet.css"/>
<script src="index_json.js"></script>
<script src="index.js"></script>
<header id="project-title">test-project</header>
<main>
  <div id="sidebar-left" path="" class="col-xs-6 col-sm-3 col-md-2 sidebar sidebar-offcanvas-left"></div>
  <div id="main-content" class="col-xs-12 col-sm-9 col-md-8 main-content">
    <h3 id="0000000000000000000000000000000000000000">f</h3>
    <p>void f(int I, int J)</p>
    <p>
      Defined at line 
      <a href="test.cpp#10">10</a>
       of file 
      <a href="test.cpp">test.cpp</a>
    </p>
    <div>
      <div>
        <p> Brief description.</p>
        <p> Extended description that continues onto the next line.</p>
        <p> Comment with html entities: &amp;, &lt;, &gt;, &quot;, &apos;.</p>
      </div>
    </div>
  </div>
  <div id="sidebar-right" class="col-xs-6 col-sm-6 col-md-2 sidebar sidebar-offcanvas-right"></div>
</main>
<footer>
  <span class="no-break">)raw" +
                         ClangDocVersion + R"raw(</span>
</footer>
)raw";

  EXPECT_EQ(Expected, Actual.str());
}

} // namespace doc
} // namespace clang
