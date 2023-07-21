Feature: Oasis Certification Tests
    The type db

    Background:
            an empty database

    Scenario: Using a table of oasis certifications to validate

        Given a table with the following certifications
            | AIM  |
            | LIM |
            | MAS   |
            | SIEM   |
            | TDS   |
            | TIP   |
            | TMS   |
            | SXC   |
            | SXP   |
        When the certification profile is run
        Then the expected flags are asserted and report is generated
