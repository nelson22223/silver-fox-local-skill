"""防止后续把面向人的 Markdown 正文改回英文。"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HAN = re.compile(r"[\u4e00-\u9fff]")
TABLE_SEPARATOR = re.compile(r"[\s|:-]+")


class ChineseMarkdownTest(unittest.TestCase):
    def test_all_markdown_prose_uses_chinese(self) -> None:
        documents = sorted(ROOT.rglob("*.md"))
        self.assertTrue(documents)
        for path in documents:
            in_fence = False
            in_frontmatter = False
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if number == 1 and line == "---":
                    in_frontmatter = True
                    continue
                if in_frontmatter:
                    if line == "---":
                        in_frontmatter = False
                    continue
                if line.startswith("```"):
                    in_fence = not in_fence
                    continue
                if (in_fence or not line.strip() or line.lstrip().startswith("|")
                        or TABLE_SEPARATOR.fullmatch(line)):
                    continue
                with self.subTest(file=str(path.relative_to(ROOT)), line=number):
                    self.assertRegex(line, HAN, "Markdown 正文应使用中文；代码及字段名可保留原文")


if __name__ == "__main__":
    unittest.main()
