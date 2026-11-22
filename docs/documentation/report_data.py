"""
PhishIntel VTU Project Report — Master Data Aggregator
Aggregates all Front Matter, Chapters 1-10, References, Appendices, and Tables.
"""

from content_front_matter import FRONT_MATTER
from content_chapters_1_3 import CHAPTER_1, CHAPTER_2, CHAPTER_3
from content_chapters_4_6 import CHAPTER_4, CHAPTER_5, CHAPTER_6
from content_chapters_7_8 import CHAPTER_7, CHAPTER_8
from content_chapters_9_10 import CHAPTER_9, CHAPTER_10
from content_references_appendices import REFERENCES, APPENDICES
from content_tables_figures import TABLES_DATA

REPORT_STRUCTURE = {
    "front_matter": FRONT_MATTER,
    "chapters": [
        CHAPTER_1,
        CHAPTER_2,
        CHAPTER_3,
        CHAPTER_4,
        CHAPTER_5,
        CHAPTER_6,
        CHAPTER_7,
        CHAPTER_8,
        CHAPTER_9,
        CHAPTER_10,
    ],
    "references": REFERENCES,
    "appendices": APPENDICES,
    "tables": TABLES_DATA,
}

