package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	sq "github.com/Masterminds/squirrel"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/charmbracelet/log"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/labstack/echo/v5"
)

type space struct {
	Name         string `json:"name" validate:"required"`
	AccesControl acces  `json:"accesControl"`
	Expired      string `json:"expired"`
}

type acces struct {
	Type     string `json:"type"`
	Password string `json:"password"`
	Emails   string `json:"emails"`
}

func create(db *sql.DB, valid *validator.Validate, log *log.Logger) echo.HandlerFunc {
	return func(ctx *echo.Context) (err error) {
		space := new(space)

		if err = ctx.Bind(space); err != nil {
			log.Error(err.Error())
			return fmt.Errorf("")
		}

		if err = valid.Struct(space); err != nil {
			log.Error(err.Error())
			return
		}

		tx, err := db.Begin()
		if err != nil {
			log.Error(err.Error())
			return err
		}

		switch space.AccesControl.Type {
		case "password":

			if _, err = sq.Insert("spaces").Columns("id", "name", "password", "acces_control", "expired").
				Values(uuid.NewString(), space.Name, space.AccesControl.Password, space.AccesControl.Type, space.Expired).
				RunWith(tx).ExecContext(context.Background()); err != nil {
				log.Error(err.Error())
				return fmt.Errorf("")
			}

		case "emails":

			spaceID := uuid.NewString()

			if _, err = sq.Insert("spaces").Columns("id", "name", "acces_control", "expired").
				Values(spaceID, space.Name, space.AccesControl.Type, space.Expired).
				RunWith(tx).ExecContext(context.Background()); err != nil {
				log.Error(err.Error())
				return err
			}

			statement := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

			query := statement.Insert("whitelist").Columns("email", "space_id")

			for _, email := range space.AccesControl.Emails {
				query = query.Values(email, spaceID)
			}

			query = query.Suffix("ON CONFLICT (email) DO NOTHING")

			_, err = query.RunWith(tx).ExecContext(context.Background())
			if err != nil {
				log.Error(err.Error())
				return err
			}

		case "public":

			if _, err = sq.Insert("spaces").
				Columns("id", "name", "acces_control", "expired").
				Values(uuid.NewString(), space.Name, space.AccesControl.Type, space.Expired).RunWith(tx).
				ExecContext(context.Background()); err != nil {
				log.Error(err.Error())
				return fmt.Errorf("")
			}

		default:
			return fmt.Errorf("")
		}

		if err = tx.Commit(); err != nil {
			log.Error(err.Error())
			return fmt.Errorf("")
		}

		return ctx.NoContent(http.StatusOK)
	}
}

func drop(db *sql.DB, valid *validator.Validate) echo.HandlerFunc {
	return func(ctx *echo.Context) (err error) {
		spaces := []string{}

		if err = ctx.Bind(spaces); err != nil {
			log.Error(err.Error())
			return echo.NewHTTPError()
		}

		statement := sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

		query := statement.Delete("whitelist").
			Where(sq.Eq{"spaces": spaces})

		tx, err := db.Begin()
		if err != nil {
			return echo.NewHTTPError()
		}

		if _, err := query.RunWith(tx).ExecContext(context.Background()); err != nil {
			log.Error(err.Error())
			return echo.NewHTTPError()
		}

		if err = tx.Commit(); err != nil {
			log.Error(err.Error())
			return echo.NewHTTPError()
		}

		return ctx.NoContent(http.StatusOK)
	}
}

func up(db *sql.DB, box *s3.Client, valid *validator.Validate, print *log.Logger) echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
		req := struct {
			space  string
			object string
		}{}

		if err = c.Bind(req); err != nil {
			print.Error(err.Error())
			return echo.NewHTTPError()
		}

		tx, err := db.BeginTx(c.Request().Context(), nil)
		if err != nil {
			print.Error(err.Error())
			return echo.NewHTTPError()
		}
		defer tx.Commit()

		row := sq.Select("id").From("spaces").Where(sq.Eq{"name": req.space}).RunWith(tx).QueryRow()

		var spaceID string
		if err = row.Scan(spaceID); err != nil {
			print.Error(err.Error())
			return echo.NewHTTPError()
		}

		objectID := uuid.NewString()
		if _, err = sq.Insert("files").Columns("id", "name", "user_id", "space_id").Values(objectID, req.object, current(c), spaceID).RunWith(tx).Exec(); err != nil {
			print.Error(err.Error())
			return echo.NewHTTPError()
		}

		presign := s3.NewPresignClient(box)

		bucket := "main"
		key := fmt.Sprintf("%s/%s/%s", current(c), req.space, req.object)
		duration := 5 * time.Minute

		request, err := sign(c.Request().Context(), presign, bucket, key, duration)
		if err != nil {
			_ = tx.Rollback()
			print.Error(err.Error())
			return echo.NewHTTPError()
		}

		return c.String(http.StatusOK, request.URL)
	}
}

func remove() echo.HandlerFunc {
	return func(c *echo.Context) (err error) {
	}
}

func sign(ctx context.Context, presign *s3.PresignClient, bucket string, key string, lifetime time.Duration) (*v4.PresignedHTTPRequest, error) {
	request, err := presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}, func(opts *s3.PresignOptions) {
		opts.Expires = lifetime
	})

	if err != nil {
		return nil, err
	}
	return request, nil
}
