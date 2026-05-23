from scanner.database import get_connection, init_db


def test_init_db_creates_api_jobs_table(tmp_path) -> None:
    db_path = tmp_path / "vulscan-test.db"

    init_db(db_path)

    with get_connection(db_path) as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'api_jobs'"
        ).fetchone()

    assert row is not None
