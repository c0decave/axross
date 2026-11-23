"""The Markdown reader's tests and elapsed time: the pytest markers ``timing`` and ``budgets``, and budget().

A test passes or fails by its content, by elapsed time, or by both:

- **Its content only** - what the page shows, what an export holds, what is refused: it blocks a release.
- **Elapsed time only** (:data:`TIMING`, the marker ``timing``) - a heartbeat's gap or a turn's CPU time
  within a budget and nothing else asserted: the freeze sweep, the stress grids. On a shared CI runner about
  twice as slow as a developer's machine they fail without a bug: the standalone's CI runs them in a job of
  their own that does not block (.github/workflows/tests.yml, ``-m "timing or budgets"``).
- **Both** (:data:`BUDGETS`, the marker ``budgets``): split in the test itself. Its content is asserted with
  ``assert`` and blocks; each duration goes through :func:`budget` (and the helpers that measure one:
  tests/markdown_heartbeat.py's assert_responsive, bugs22's within_turn, the _quick helpers) or
  :func:`until_within` (a wait whose speed is the claim: the condition must come true - that blocks - and
  in time - that is a budget). In the blocking job (``-m "not timing"``) a budget missed is a warning
  (:data:`SOFT`); in the timing job and locally it fails. A security or safety test is never in TIMING:
  its assertions block (tests/test_markdown_timing_marks.py checks that every assertion of a TIMING test
  is a duration's, and the names).

Locally nothing changes: ``python -m pytest tests`` runs everything at full strictness, the bar for every
change.

:data:`TIMING` and :data:`BUDGETS` are what tests/test_markdown_timing_marks.py's scan of the tests finds -
the scan fails when a test asserting a duration with a plain ``assert`` is in neither TIMING nor split, or
when a listed test asserts anything but a duration; :data:`BY_HAND` the tests the scan cannot see (a wait
made of fixed pumps, durations measured in a child), each with why. The conftests apply the markers
(:func:`mark`) and set :data:`SOFT` (:func:`configure`).
"""

from __future__ import annotations

import os
import sys
import time
import warnings

MARKER = "timing"
MARKER_HELP = "timing: passes or fails by elapsed time only (heartbeats, turn budgets, the freeze sweep)"
#: The marker of a test that asserts its content (blocking) and a duration (budget(): a warning in the
#: blocking job).
BUDGETS_MARKER = "budgets"
BUDGETS_HELP = ("budgets: asserts its content and a duration - the duration (budget()) a warning under "
                '-m "not timing", a failure otherwise')
#: How long a wait for a page to be ready waits at most: no budget - it goes on as soon as it is ready.
READY_SECONDS = 120
#: The environment variable that makes every budget a warning (``warn``) - as ``-m "not timing"`` does.
ENV = "AXROSS_TIMING_BUDGETS"
#: Whether a budget missed is a warning (the blocking job: -m "not timing") - else it fails.
SOFT = os.environ.get(ENV, "").strip().lower() == "warn"
#: The budgets missed in this run under SOFT (their messages).
MISSED: list[str] = []


class TimingBudgetWarning(UserWarning):
    """A duration over its budget in the blocking job (SOFT): said, not failed - the timing job fails it."""


class BudgetMissed(AssertionError):
    """A duration over its budget (budget(), not SOFT)."""


def budget(ok, message="", error=None) -> bool:
    """A duration's assertion: *ok* (its budget held) - else BudgetMissed (or *error*: the heartbeat's Frozen,
    which the conftest measures again), or under SOFT a warning (and on GitHub Actions an annotation). Returns
    *ok*."""
    if ok:
        return True
    text = str(message) if message != "" else "a duration over its budget"
    if not SOFT:
        raise (error or BudgetMissed)(message if error is not None else text)
    MISSED.append(text)
    warnings.warn(TimingBudgetWarning(text), stacklevel=2)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=timing budget (not blocking)::{text[:900]}", file=sys.stderr)
    return False


def until_within(wait, condition, seconds: float, *rest) -> bool:
    """*wait(condition, timeout, *rest)* (a test's until) with READY_SECONDS at least - whether *condition*
    came true, which the caller asserts (it blocks) - and the time it took budgeted against *seconds*."""
    began = time.monotonic()
    came = wait(condition, max(seconds, READY_SECONDS), *rest)
    took = time.monotonic() - began
    if came:
        budget(took <= seconds, f"came true after {took:.2f} s, more than {seconds} s")
    return came


def configure(config) -> None:
    """(the conftests' pytest_configure) the markers; SOFT under ``-m "not timing"`` (the blocking job)."""
    global SOFT
    config.addinivalue_line("markers", MARKER_HELP)
    config.addinivalue_line("markers", BUDGETS_HELP)
    expression = " ".join(str(getattr(config.option, "markexpr", "") or "").split())
    if expression == f"not {MARKER}":
        SOFT = True

#: module::test (every parameter of it).
TIMING = frozenset({
    "test_markdown_emoji_font_scan_budget::test_sad_opening_a_markdown_file_does_not_hold_the_window_with_slow_fonts",
    "test_markdown_freeze_sweep::test_sad_no_text_of_the_sweep_freezes_the_window",
    "test_markdown_freeze_sweep::test_sad_the_heartbeat_sees_a_worker_holding_the_lock_not_the_gui_s_own_work",
    "test_markdown_reader_bugs13::test_guard_no_formula_takes_long_to_lay_out",
    "test_markdown_reader_bugs14::test_sad_thousands_of_spans_in_a_line_never_hold_up_the_window",
    "test_markdown_reader_bugs15::test_guard_one_huge_block_never_holds_up_the_window",
    "test_markdown_reader_bugs16::test_guard_a_big_block_in_a_container_never_holds_up_the_window",
    "test_markdown_reader_bugs17::test_sad_a_list_of_thousands_of_notes_is_still_cut_between_its_notes",
    "test_markdown_reader_bugs19::test_sad_the_window_shows_the_first_part_of_a_long_text_of_one_kind_in_time",
    "test_markdown_reader_bugs22::test_sad_a_sample_of_the_grid_holds_no_turn",
    "test_markdown_reader_bugs22::test_sad_find_and_copy_of_a_page_laid_out_to_its_end_hold_no_turn",
    "test_markdown_reader_bugs22::test_sad_find_copy_and_pdf_of_a_review_case_hold_no_turn",
    "test_markdown_reader_bugs22::test_sad_find_copy_pdf_and_the_preview_of_the_grid_hold_no_turn",
    "test_markdown_reader_bugs22::test_sad_the_preview_of_3000_code_blocks_holds_no_turn_while_typing",
    "test_markdown_reader_bugs22::test_sad_the_reviews_cases_hold_no_turn",
    "test_markdown_reader_bugs22::test_slow_the_whole_grid_holds_no_turn",
    "test_markdown_reader_bugs23::test_sad_a_big_table_s_parts_hold_no_turn",
    "test_markdown_reader_bugs23::test_sad_a_long_line_of_raw_html_holds_no_turn",
    "test_markdown_reader_bugs23::test_sad_a_pdf_of_a_big_table_holds_no_turn",
    "test_markdown_reader_bugs23::test_sad_a_pdf_of_a_long_line_of_raw_html_holds_no_turn",
    "test_markdown_reader_bugs23::test_sad_qt_s_own_parser_holds_no_turn",
    "test_markdown_reader_bugs23::test_sad_the_passes_before_qt_s_own_parser_are_linear",
    "test_markdown_reader_bugs24::test_happy_every_stress_meter_measures_the_gap_too",
    "test_markdown_reader_bugs24::test_sad_a_line_of_backticks_freezes_no_window_on_its_own_or_in_a_big_file",
    "test_markdown_reader_bugs24::test_sad_qt_s_own_parser_cuts_these_paragraphs_and_parts",
    "test_markdown_reader_bugs24::test_sad_the_heartbeat_sees_a_worker_that_holds_pythons_lock_the_cpu_meter_does_not",
    "test_markdown_reader_bugs25::test_sad_a_heading_of_spaced_words_freezes_no_window",
    "test_markdown_reader_bugs25::test_sad_a_paragraph_of_kaithi_number_signs_holds_no_turn",
    "test_markdown_reader_bugs25::test_sad_fences_never_closed_freeze_no_window",
    "test_markdown_reader_bugs25::test_sad_reading_a_table_of_20_000_rows_to_its_end_holds_no_turn",
    "test_markdown_reader_bugs25::test_sad_those_paragraphs_hold_no_turn",
    "test_markdown_reader_bugs26::test_sad_a_block_tag_s_line_of_2_mb_freezes_no_window",
    "test_markdown_reader_bugs26::test_sad_export_pdf_and_print_of_a_2_mb_html_block_keep_the_window_answering",
    "test_markdown_reader_bugs6::test_sad_a_paragraph_of_many_raw_tags_is_sanitized_in_linear_time",
    "test_markdown_reader_bugs27::test_sad_a_missing_anchor_holds_no_turn",
    "test_markdown_reader_bugs27::test_sad_a_theme_switch_on_a_page_read_to_its_end_holds_no_turn",
})

#: module::test of the tests that assert their content and a duration - the duration through budget() or a
#: helper that budgets (the marker budgets: run strictly by the timing job, a duration a warning in the
#: blocking one).
BUDGETS = frozenset({
    "test_markdown_emoji_font_scan_budget::test_sad_hundreds_of_fonts_without_emoji_do_not_hold_the_window",
    "test_markdown_full::test_edge_a_word_of_a_megabyte_is_cut_in_linear_time",
    "test_markdown_full::test_edge_the_columns_of_a_huge_table_are_fitted_in_time",
    "test_markdown_full::test_sad_autolinks_of_hostile_lines_stay_linear",
    "test_markdown_image_safety::test_safety_a_slow_svg_is_stopped_by_the_documents_time",
    "test_markdown_image_safety::test_safety_a_use_bomb_as_a_data_image_is_refused",
    "test_markdown_image_safety::test_safety_a_use_bomb_is_refused_at_once",
    "test_markdown_preview_off_gui_thread::test_sad_a_long_table_does_not_freeze_the_window",
    "test_markdown_preview_off_gui_thread::test_sad_crafted_emphasis_does_not_freeze_the_window",
    "test_markdown_reader_bugs10::test_sad_a_drop_at_95_percent_shows_its_place_at_once",
    "test_markdown_reader_bugs10::test_sad_find_of_the_last_word_of_a_long_page_is_fast",
    "test_markdown_reader_bugs11::test_guard_a_copy_across_a_gap_holds_all_of_it",
    "test_markdown_reader_bugs11::test_guard_a_footnote_link_and_its_way_back",
    "test_markdown_reader_bugs11::test_guard_a_live_reload_keeps_the_place",
    "test_markdown_reader_bugs11::test_guard_a_reload_keeps_the_place_after_a_jump",
    "test_markdown_reader_bugs11::test_guard_a_reload_of_a_short_page_keeps_the_place",
    "test_markdown_reader_bugs11::test_guard_an_anchor_jump_puts_its_heading_on_top",
    "test_markdown_reader_bugs11::test_guard_find_in_order_across_gaps_and_round",
    "test_markdown_reader_bugs11::test_guard_folding_and_unfolding_details_keeps_the_place",
    "test_markdown_reader_bugs11::test_guard_the_outline_lists_every_heading",
    "test_markdown_reader_bugs11::test_sad_find_after_ctrl_end_then_home_takes_the_first_match_first",
    "test_markdown_reader_bugs11::test_sad_md4c_a_page_of_many_tables_is_made_whole_without_a_freeze",
    "test_markdown_reader_bugs11::test_sad_md4c_parts_carry_the_link_definitions_they_use_only",
    "test_markdown_reader_bugs12::test_sad_an_anchor_in_a_piece_not_parsed_yet_is_gone_to",
    "test_markdown_reader_bugs12::test_sad_select_all_then_copy_copies_all_of_a_long_page_at_once",
    "test_markdown_reader_bugs12::test_sad_the_terminal_shows_a_long_text_with_footnotes_at_once",
    "test_markdown_reader_bugs13::test_guard_a_page_of_hostile_formulas_never_holds_up_the_window",
    "test_markdown_reader_bugs13::test_guard_a_selection_across_gaps_copies_what_the_page_shows",
    "test_markdown_reader_bugs14::test_guard_nested_formulas_never_hold_up_the_window",
    "test_markdown_reader_bugs15::test_hostile_a_folders_readme_is_checked_as_a_link",
    "test_markdown_reader_bugs15::test_sad_a_copy_holds_items_numbers_and_a_formulas_number_once",
    "test_markdown_reader_bugs16::test_guard_copy_of_many_formulas_takes_a_piece_a_turn",
    "test_markdown_reader_bugs17::test_guard_a_big_block_in_any_container_never_holds_up_the_window",
    "test_markdown_reader_bugs17::test_sad_a_deep_quote_after_a_lists_marker_is_shown_flatter_everywhere",
    "test_markdown_reader_bugs17::test_sad_a_drag_makes_its_text_only_when_asked",
    "test_markdown_reader_bugs17::test_sad_a_reload_during_a_copy_says_the_copy_was_cancelled",
    "test_markdown_reader_bugs17::test_sad_ctrl_end_shows_the_end_at_once",
    "test_markdown_reader_bugs17::test_sad_formulas_past_a_headings_hundred_are_said_and_quick",
    "test_markdown_reader_bugs18::test_guard_random_short_markdown_never_raises_or_hangs",
    "test_markdown_reader_bugs18::test_sad_a_parse_past_its_time_shows_the_text_as_written",
    "test_markdown_reader_bugs18::test_sad_a_rule_that_never_moves_on_cannot_hang_the_parse",
    "test_markdown_reader_bugs18::test_sad_export_holds_up_the_window_no_longer",
    "test_markdown_reader_bugs19::test_sad_a_formula_nested_thousands_deep_is_shown_without_an_error",
    "test_markdown_reader_bugs19::test_sad_a_line_of_10_mb_never_holds_the_event_loop",
    "test_markdown_reader_bugs19::test_sad_a_short_text_of_brackets_inside_each_other_is_parsed_off_the_gui_thread",
    "test_markdown_reader_bugs19::test_sad_braced_is_linear_and_capped",
    "test_markdown_reader_bugs19::test_sad_mdcat_draws_a_table_of_100000_rows_as_it_goes_with_little_memory",
    "test_markdown_reader_bugs19::test_sad_mdcat_shows_a_line_of_10_mb_in_seconds_with_little_memory",
    "test_markdown_reader_bugs19::test_sad_mdcat_shows_a_link_of_a_megabyte_in_seconds",
    "test_markdown_reader_bugs19::test_sad_task_lists_find_their_list_in_one_pass",
    "test_markdown_reader_bugs19::test_sad_the_gui_thread_waits_for_pythons_lock_a_millisecond_at_most_once_a_worker_ran",
    "test_markdown_reader_bugs20::test_sad_a_lexer_stuck_in_backtracking_leaves_the_terminal_and_the_export_plain",
    "test_markdown_reader_bugs20::test_sad_a_lexer_stuck_in_backtracking_never_holds_the_window",
    "test_markdown_reader_bugs20::test_sad_a_long_line_of_spans_never_holds_the_window",
    "test_markdown_reader_bugs20::test_sad_a_long_text_with_inline_notes_shows_its_first_part_at_once",
    "test_markdown_reader_bugs20::test_sad_linkify_finds_every_link_of_a_long_line_in_pieces",
    "test_markdown_reader_bugs20::test_sad_mdcat_stops_when_its_pipe_closes",
    "test_markdown_reader_bugs20::test_sad_the_editor_preview_follows_the_line_typed_at",
    "test_markdown_reader_bugs20::test_sad_the_window_shows_a_long_text_with_inline_notes_in_parts",
    "test_markdown_reader_bugs21::test_sad_a_missing_file_says_why_in_the_page",
    "test_markdown_reader_bugs21::test_sad_a_note_cited_100000_times_shows_its_first_ways_back_and_a_count",
    "test_markdown_reader_bugs21::test_sad_a_page_of_many_headings_is_laid_out_in_linear_time",
    "test_markdown_reader_bugs21::test_sad_clamping_images_looks_at_a_bounded_number_a_turn",
    "test_markdown_reader_bugs21::test_sad_no_hostile_shape_in_any_container_holds_the_window",
    "test_markdown_reader_bugs21::test_sad_the_editor_colours_every_common_language",
    "test_markdown_reader_bugs22::test_sad_a_folder_given_opens_its_readme",
    "test_markdown_reader_bugs22::test_sad_a_missing_file_is_said_in_words",
    "test_markdown_reader_bugs23::test_sad_closing_the_window_during_an_export_ends_the_export",
    "test_markdown_reader_bugs24::test_sad_a_letter_with_ninety_nine_thousand_marks_holds_no_turn",
    "test_markdown_reader_bugs24::test_sad_a_table_shown_as_written_has_its_lines_cut",
    "test_markdown_reader_bugs24::test_sad_a_text_of_a_few_kilobytes_is_parsed_on_a_worker",
    "test_markdown_reader_bugs24::test_sad_a_zoom_on_a_big_table_read_to_its_end_holds_no_later_turn",
    "test_markdown_reader_bugs24::test_sad_code_spans_are_found_in_one_pass",
    "test_markdown_reader_bugs24::test_sad_ctrl_end_and_ctrl_home_go_there_on_a_page_laid_out_whole",
    "test_markdown_reader_bugs24::test_sad_details_are_folded_in_qt_s_own_parser_too",
    "test_markdown_reader_bugs24::test_sad_export_asks_for_the_file_before_the_page_is_laid_out_whole",
    "test_markdown_reader_bugs24::test_sad_find_without_a_match_on_a_big_page_is_quick",
    "test_markdown_reader_bugs24::test_sad_markdown_it_s_inline_rules_are_linear",
    "test_markdown_reader_bugs24::test_sad_print_asks_once_and_first",
    "test_markdown_reader_bugs24::test_sad_qt_s_own_parser_s_html_export_holds_no_turn",
    "test_markdown_reader_bugs24::test_sad_the_emoji_scan_is_all_of_it_under_its_deadline",
    "test_markdown_reader_bugs24::test_sad_the_maths_font_check_asks_the_font_alone",
    "test_markdown_reader_bugs25::test_happy_the_heartbeat_s_budget_is_tight_and_measured_again",
    "test_markdown_reader_bugs25::test_sad_a_heading_line_of_spaced_words_is_cut_at_once",
    "test_markdown_reader_bugs25::test_sad_a_page_is_made_with_the_collector_held",
    "test_markdown_reader_bugs25::test_sad_a_run_of_format_signs_is_no_one_character_no_cut_goes_into",
    "test_markdown_reader_bugs25::test_sad_a_zoom_on_a_page_of_100_000_headings_holds_no_turn",
    "test_markdown_reader_bugs25::test_sad_copying_30_000_formulas_holds_no_turn",
    "test_markdown_reader_bugs25::test_sad_export_html_of_a_big_page_keeps_the_window_answering",
    "test_markdown_reader_bugs25::test_sad_fences_never_closed_are_read_in_one_pass",
    "test_markdown_reader_bugs25::test_sad_find_while_the_rest_of_a_page_is_parsed_waits_little_for_python_s_lock",
    "test_markdown_reader_bugs25::test_sad_one_page_is_made_at_a_time_and_the_gui_thread_never_waits_for_it",
    "test_markdown_reader_bugs25::test_sad_the_emoji_check_is_quick_on_a_big_text_of_other_letters",
    "test_markdown_reader_bugs25::test_sad_the_emoji_scan_looks_at_the_clock_at_each_short_code",
    "test_markdown_reader_bugs25::test_sad_the_long_line_check_looks_from_a_line_s_start_only",
    "test_markdown_reader_bugs25::test_sad_the_space_run_pattern_looks_from_a_run_s_start_only",
    "test_markdown_reader_bugs26::test_sad_a_missing_anchor_is_said_at_once",
    "test_markdown_reader_bugs26::test_sad_a_resize_of_10_000_sections_read_to_their_end_holds_no_turn",
    "test_markdown_reader_bugs26::test_sad_a_theme_switch_paints_image_boxes_again_without_laying_out_the_page",
    "test_markdown_reader_bugs26::test_sad_a_zoom_on_10_000_sections_read_to_their_end_holds_no_turn",
    "test_markdown_reader_bugs26::test_sad_find_and_zoom_on_a_long_code_block_laid_out_hold_no_turn",
    "test_markdown_reader_bugs26::test_sad_highlighted_code_weighs_its_spans_too",
    "test_markdown_reader_bugs26::test_sad_openers_never_closed_are_read_in_one_pass",
    "test_markdown_reader_bugs28::test_sad_a_resize_that_keeps_the_text_s_width_lays_nothing_out_again",
    "test_markdown_reader_bugs28::test_sad_the_comment_rules_stay_linear",
    "test_markdown_reader_bugs5::test_sad_the_terminal_shows_the_start_of_a_long_list_at_once",
    "test_markdown_reader_bugs6::test_sad_markdown_its_page_shows_the_start_of_a_long_file_at_once",
    "test_markdown_reader_bugs7::test_sad_a_long_run_of_spaces_takes_qts_own_parser_no_time",
    "test_markdown_reader_bugs8::test_sad_a_paragraph_of_many_dropped_tags_takes_no_time",
    "test_markdown_reader_bugs9::test_sad_an_idle_page_is_not_laid_out_again_and_again",
    "test_markdown_reader_features::test_sad_hostile_math_is_bounded_and_escaped",
    "test_markdown_themes::test_sad_rapid_switching_is_rate_limited_to_one_change_a_moment",
    "test_markdown_themes::test_sad_switching_the_theme_of_a_big_page_keeps_the_window_answering",
    "test_markdown_update::test_sad_a_check_and_an_update_never_run_on_the_gui_thread",
    "test_markdown_viewer::test_happy_the_editor_shows_a_live_preview",
    "test_markdown_viewer_window::test_happy_a_file_changed_on_disk_is_shown_anew_where_it_was",
})

#: module::test -> why it depends on elapsed time (the scan does not see it).
BY_HAND = {
    "test_markdown_reader_bugs18::test_sad_a_pdf_of_a_big_page_is_whole":
        "the PDF of a page parsed against markdown_doc's parse deadline (PARSE_SECONDS): on a runner about twice "
        "as slow a part past it is shown as written - sections missing by elapsed time",
    "test_markdown_regex_audit::test_sad_the_audit_flags_the_patterns_review_24_found":
        "times the patterns in a child process (their growth at doubling lengths)",
}


def key(item) -> str:
    """module::test of a collected pytest item (its parameters left out)."""
    module = item.module.__name__.rsplit(".", 1)[-1] if getattr(item, "module", None) else ""
    return f"{module}::{getattr(item, 'originalname', None) or item.name.split('[', 1)[0]}"


def mark(items) -> int:
    """The marker ``timing`` on each of *items* listed in TIMING or BY_HAND, ``budgets`` on each in BUDGETS:
    how many got ``timing``."""
    import pytest

    count = 0
    for item in items:
        name = key(item)
        if name in TIMING or name in BY_HAND:
            item.add_marker(getattr(pytest.mark, MARKER))
            count += 1
        elif name in BUDGETS:
            item.add_marker(getattr(pytest.mark, BUDGETS_MARKER))
    return count
