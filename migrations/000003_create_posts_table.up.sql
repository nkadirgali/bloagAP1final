CREATE TABLE IF NOT EXISTS posts (
        id bigserial PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users ON DELETE CASCADE,
    date timestamp(0) with time zone NOT NULL,
    text text NOT NULL
);
