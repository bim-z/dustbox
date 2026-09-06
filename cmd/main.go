/*
Copyright (C) 2026 Berlian Bima Seto

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"charm.land/bubbles/v2/progress"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/asaskevich/govalidator"
	"github.com/charmbracelet/fang"
	"github.com/karrick/godirwalk"
	"github.com/labstack/echo/v5"
	"github.com/nbutton23/zxcvbn-go"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
	"resty.dev/v3"
)

func main() {
	dustbox := dustbox()

	dustbox.AddGroup(auth)

	c := resty.New()

	dustbox.AddCommand(signin(), signout(), create(c), drop(c), up(c), remove(c))

	_ = fang.Execute(dustbox.Context(), dustbox)
}

var auth = &cobra.Group{
	ID:    "auth",
	Title: "Authentication",
}

func signin() *cobra.Command {
	return &cobra.Command{
		Use:     "signin [provider]",
		GroupID: "auth",
		Short:   "Sign in using an external provider (google or github)",
		Args:    cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if prov := args[0]; prov != "google" && prov != "github" {
				return fmt.Errorf("invalid login provider '%s'. Please use either 'google' or 'github'", prov)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			provider := args[0]

			authURL := fmt.Sprintf("https://your-backend.com/auth/login/%s", provider)

			cmd.Printf("Opening your browser to authenticate with %s...\n", provider)
			if err = browser.OpenURL(authURL); err != nil {
				return fmt.Errorf("failed to open the browser automatically. Please visit this link manually to log in:\n%s\nError details: %w", authURL, err)
			}

			// Channel to orchestrate the callback shutdown
			shutdown := make(chan error, 1)

			// Setup Echo router
			// NOTE: In standard Labstack Echo, 'echo.Context' is an interface, so we don't use '*'
			mux := echo.New()

			mux.GET("/auth/:token", func(c *echo.Context) (err error) {
				token := c.Param("token")

				if token == "" {
					err := errors.New("the authentication token returned by the server was empty")
					shutdown <- err
					return c.String(http.StatusBadRequest, "Authentication failed: Token is empty.")
				}

				currentUser, err := user.Current()
				if err != nil {
					err = fmt.Errorf("failed to retrieve current system user profile: %w", err)
					shutdown <- err
					return c.String(http.StatusInternalServerError, "Internal system error. Please check your CLI terminal.")
				}

				if err = keyring.Set("dustbox", currentUser.Uid, token); err != nil {
					err = fmt.Errorf("failed to securely store your token in the system keychain: %w", err)
					shutdown <- err
					return c.String(http.StatusInternalServerError, "Failed to save credentials securely.")
				}

				_ = c.String(http.StatusOK, "Authentication successful! You can now close this tab and return to your terminal.")
				shutdown <- nil
				return nil
			})

			server := &http.Server{
				Addr:    ":8080",
				Handler: mux,
			}

			go func() {
				// ERROR: Handle cases where port 8080 is already in use by another app
				if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					shutdown <- fmt.Errorf("local callback server failed to start on port 8080 (is another app using it?): %w", err)
				}
			}()

			cmd.Println("Waiting for authentication callback on port 8080...")

			// Block and wait for either a success or failure signal from the callback handler/server
			err = <-shutdown
			if err != nil {
				return err
			}

			// Graceful shutdown of the local server
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)

			cmd.Println("Successfully signed in! Your session is now active.")
			return nil
		},
	}
}

// contextKey is defined to avoid using basic types (strings) as context keys,
// which prevents potential key collisions in complex applications.
type contextKey string

const tokenKey contextKey = "token"

func signout() *cobra.Command {
	return &cobra.Command{
		Use:     "signout",
		GroupID: "auth",
		Short:   "Sign out from your account and clear saved credentials",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			currentUser, err := user.Current()
			if err != nil {
				// ERROR: Failed to detect the current OS user.
				return fmt.Errorf("failed to determine your system user profile: %w", err)
			}

			if err = keyring.Delete("dustbox", currentUser.Uid); err != nil {
				// ERROR: The secret could not be removed from the system keychain.
				return fmt.Errorf("could not remove saved credentials from the system keychain: %w", err)
			}

			cmd.Println("Successfully signed out. Your credentials have been cleared.")
			return nil
		},
	}
}

func getToken(cmd *cobra.Command, args []string) (err error) {
	currentUser, err := user.Current()
	if err != nil {
		// ERROR: Cannot fetch user, blocking the authentication process.
		return fmt.Errorf("authentication failed: unable to read system user profile: %w", err)
	}

	token, err := keyring.Get("dustbox", currentUser.Uid)
	if err != nil {
		// ERROR: No token found or keychain is locked.
		return fmt.Errorf("authentication required: no active session found. Please login first: %w", err)
	}

	// NOTE: Using a custom type 'tokenKey' instead of a raw string "token"
	// is the idiomatic Go way to pass values through context safely.
	ctx := context.WithValue(cmd.Context(), tokenKey, token)

	cmd.SetContext(ctx)
	return nil
}

type space struct {
	Name         string       `json:"name"`
	AccesControl accesControl `json:"accesControl"`
	Expired      string       `json:"expired"`
}

type accesControl struct {
	Type     string `json:"type"`
	Password string `json:"password"`
	Emails   string `json:"emails"`
}

type message struct {
	Message string `json:"message"`
}

var durations = []string{
	"1 day", "3 days", "7 days",
	"30 days", "60 days", "1 year", "never",
}

// root command
func dustbox() *cobra.Command {
	return &cobra.Command{
		Use:   "dustbox",
		Short: "Dustbox CLI file sharing tool",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			return cmd.Help()
		},
	}
}

// create new space
func create(c *resty.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "create",
		Short:   "Create a new secure space",
		PreRunE: getToken,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			spaceData := new(space)

			if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
				var control string
				accesList := huh.NewOptions[string]("public", "password", "email")

				form := huh.NewForm(
					huh.NewGroup(
						huh.NewInput().
							Title("Name").
							Placeholder("Enter Space Name").
							Value(&spaceData.Name).
							Key("name").
							CharLimit(600),

						huh.NewSelect[string]().
							Title("Access Control").
							Value(&control).
							Options(accesList...),
					),
					acces(control, spaceData),
				)

				if err = form.Run(); err != nil {
					return err
				}

				spaceData.AccesControl.Type = control
				spaceData.Expired = form.GetString("expired")
			} else {
				spaceData.Name, _ = cmd.Flags().GetString("name")
				if spaceData.Name == "" {
					return fmt.Errorf("space name is required")
				}

				spaceData.AccesControl.Type, _ = cmd.Flags().GetString("control")

				if spaceData.AccesControl.Type == "password" {
					if !cmd.Flags().Changed("password") {
						return fmt.Errorf("password flag is required when access control is set to password")
					}
					spaceData.AccesControl.Password, _ = cmd.Flags().GetString("password")
					if err = passwordStrength(spaceData.AccesControl.Password); err != nil {
						return err
					}
				} else if spaceData.AccesControl.Type == "email" {
					if !cmd.Flags().Changed("emails") {
						return fmt.Errorf("emails flag is required when access control is set to email")
					}
					addrs, _ := cmd.Flags().GetString("emails")
					if err = validEmails(addrs); err != nil {
						return err
					}
					spaceData.AccesControl.Emails = addrs
				} else {
					spaceData.AccesControl.Type = "public"
				}

				spaceData.Expired, _ = cmd.Flags().GetString("expired")
				if !slices.Contains(durations, spaceData.Expired) {
					return fmt.Errorf("invalid duration. Choose from: %s", strings.Join(durations, ", "))
				}
			}

			ctx := cmd.Context()
			token, ok := ctx.Value(tokenKey).(string)
			if !ok || token == "" {
				return fmt.Errorf("unauthorized: token not found in context")
			}

			var errMsg message
			res, err := c.R().
				SetAuthToken(token).
				SetBody(spaceData).
				SetResultError(&errMsg).
				Post("/spaces") // Sesuaikan endpoint API Anda

			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}

			if res.StatusCode() != http.StatusOK {
				return fmt.Errorf("failed to create space: %s", errMsg.Message)
			}

			info(fmt.Sprintf("Space '%s' successfully created!", spaceData.Name))
			return nil
		},
	}

	cmd.Flags().BoolP("interactive", "i", false, "Run in interactive mode")
	cmd.Flags().StringP("name", "n", "", "Name of the space")
	cmd.Flags().StringP("control", "c", "public", "Access control type (public, password, email)")
	cmd.Flags().StringP("password", "p", "", "Password for the space")
	cmd.Flags().StringP("emails", "e", "", "Comma-separated emails allowed to access")
	cmd.Flags().StringP("expired", "x", "7 days", "Space expiration duration")

	return cmd
}

// delete one or more spaces
func drop(c *resty.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "drop [spaces...]",
		Short:   "Delete one or more spaces",
		PreRunE: getToken,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			ctx := cmd.Context()
			token, ok := ctx.Value(tokenKey).(string)
			if !ok {
				return fmt.Errorf("unauthorized: token not found")
			}

			var spacesToDelete []string

			if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
				var availableSpaces []string
				var errMsg message

				res, err := c.R().
					SetAuthToken(token).
					SetResultError(&errMsg).
					SetResult(&availableSpaces).
					Get("/spaces") // Sesuaikan endpoint fetch list spaces

				if err != nil {
					return fmt.Errorf("failed to fetch spaces: %w", err)
				}
				if res.StatusCode() != http.StatusOK {
					return fmt.Errorf("failed to fetch spaces: %s", errMsg.Message)
				}

				if len(availableSpaces) == 0 {
					info("No spaces available to delete.")
					return nil
				}

				opts := huh.NewOptions[string](availableSpaces...)
				form := huh.NewForm(huh.NewGroup(
					huh.NewMultiSelect[string]().
						Title("Select spaces to delete").
						Options(opts...).
						Value(&spacesToDelete),
				))

				if err = form.Run(); err != nil {
					return err
				}
			} else {
				if err = cobra.MinimumNArgs(1)(cmd, args); err != nil {
					return fmt.Errorf("please specify at least one space to delete or use --interactive")
				}
				spacesToDelete = append(spacesToDelete, args...)
			}

			if len(spacesToDelete) == 0 {
				return nil
			}

			var errMsg message
			res, err := c.R().
				SetAuthToken(token).
				SetResultError(&errMsg).
				SetBody(map[string][]string{"spaces": spacesToDelete}).
				Delete("/spaces")

			if err != nil {
				return fmt.Errorf("request failed: %w", err)
			}
			if res.StatusCode() != http.StatusOK {
				return fmt.Errorf("failed to delete space(s): %s", errMsg.Message)
			}

			info(fmt.Sprintf("Successfully dropped spaces: %s", strings.Join(spacesToDelete, ", ")))
			return nil
		},
	}

	cmd.Flags().BoolP("interactive", "i", false, "Run in interactive mode")
	return cmd
}

// upload command
func up(c *resty.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "up [files...]",
		Short: "Upload files to a space",
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var spaceName string
			var files []string

			if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
				program := tea.NewProgram(&picker{
					Space: &spaceName,
					Files: &files,
				})

				p, err := program.Run()
				if err != nil {
					return err
				}

				pick := p.(*picker)
				if pick.Err != nil {
					return pick.Err
				}
			} else {
				spaceName, _ = cmd.Flags().GetString("space")
				if spaceName == "" {
					return fmt.Errorf("space flag (--space) is required in non-interactive mode")
				}
				if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
					return fmt.Errorf("you must specify at least one file to upload")
				}
				files = args
			}

			ctx := cmd.Context()
			token, ok := ctx.Value(tokenKey).(string)
			if !ok {
				return fmt.Errorf("unauthorized: token not found")
			}

			// Setup bubbletea progress bar
			progressChan := make(chan progressMsg, len(files))
			go send(c, spaceName, token, progressChan, files...)

			prog := progress.New(progress.WithDefaultBlend())
			b := bar{
				progress:     prog,
				totalFiles:   len(files),
				progressChan: progressChan,
			}

			p := tea.NewProgram(b)
			if _, err := p.Run(); err != nil {
				return fmt.Errorf("progress bar error: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolP("interactive", "i", false, "Run in interactive mode")
	cmd.Flags().StringP("space", "s", "", "Target space name")
	return cmd
}

// remove one or more files in one space
func remove(c *resty.Client) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm [files...]",
		Short:   "Remove files from a space",
		PreRunE: getToken,
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			var spaceName string
			var filesToDelete []string
			ctx := cmd.Context()
			token, ok := ctx.Value(tokenKey).(string)
			if !ok {
				return fmt.Errorf("unauthorized: token not found")
			}

			if interactive, _ := cmd.Flags().GetBool("interactive"); interactive {
				var availableSpaces []string
				var errMsg message

				// Ambil list space yang ada
				res, err := c.R().SetAuthToken(token).SetResultError(&errMsg).SetResult(&availableSpaces).Get("/spaces")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return fmt.Errorf("failed to fetch spaces: %s", errMsg.Message)
				}

				if len(availableSpaces) == 0 {
					info("No spaces available.")
					return nil
				}

				spaceOpts := huh.NewOptions[string](availableSpaces...)
				spaceForm := huh.NewForm(huh.NewGroup(
					huh.NewSelect[string]().
						Title("Select Space").
						Options(spaceOpts...).
						Value(&spaceName),
				))

				if err = spaceForm.Run(); err != nil {
					return err
				}

				// Ambil file di dalam space terpilih
				var filesInSpace []string
				res, err = c.R().SetAuthToken(token).SetResultError(&errMsg).SetResult(&filesInSpace).Get("/spaces/" + spaceName + "/files")
				if err != nil {
					return err
				}
				if res.StatusCode() != http.StatusOK {
					return fmt.Errorf("failed to fetch files: %s", errMsg.Message)
				}

				if len(filesInSpace) == 0 {
					info("This space is already empty.")
					return nil
				}

				fileOpts := huh.NewOptions[string](filesInSpace...)
				fileForm := huh.NewForm(huh.NewGroup(
					huh.NewMultiSelect[string]().
						Title("Select files to delete").
						Options(fileOpts...).
						Value(&filesToDelete),
				))

				if err = fileForm.Run(); err != nil {
					return err
				}
			} else {
				spaceName, _ = cmd.Flags().GetString("space")
				if spaceName == "" {
					return fmt.Errorf("space flag (--space) is required")
				}
				if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
					return fmt.Errorf("specify at least one file to remove")
				}
				filesToDelete = args
			}

			if len(filesToDelete) == 0 {
				return nil
			}

			var errMsg message
			res, err := c.R().
				SetAuthToken(token).
				SetBody(map[string]any{
					"space": spaceName,
					"files": filesToDelete,
				}).
				SetResultError(&errMsg).
				Delete("/files") // Sesuaikan endpoint hapus file Anda

			if err != nil {
				return err
			}
			if res.StatusCode() != http.StatusOK {
				return fmt.Errorf("failed to delete files: %s", errMsg.Message)
			}

			info("Selected files have been removed successfully.")
			return nil
		},
	}

	cmd.Flags().BoolP("interactive", "i", false, "Run in interactive mode")
	cmd.Flags().StringP("space", "s", "", "Space name containing the files")
	return cmd
}

func acces(control string, s *space) *huh.Group {
	switch control {
	case "public":
		return huh.NewGroup(expired(&s.Expired))

	case "password":
		return huh.NewGroup(
			huh.NewInput().
				EchoMode(huh.EchoModePassword).
				CharLimit(16).
				Title("Enter Password").
				Value(&s.AccesControl.Password).
				Validate(func(val string) error {
					if val == "" {
						return fmt.Errorf("password cannot be empty")
					}
					return passwordStrength(val)
				}),
			expired(&s.Expired),
		)

	case "email":
		return huh.NewGroup(
			huh.NewText().
				Title("Whitelisted Emails").
				Placeholder("comma separated, e.g. user@test.com, admin@test.com").
				Value(&s.AccesControl.Emails).
				Validate(func(val string) error {
					return validEmails(val)
				}),
			expired(&s.Expired),
		)
	}

	return huh.NewGroup()
}

// set space expiration date
func expired(bind *string) huh.Field {
	opts := huh.NewOptions[string](durations...)
	return huh.NewSelect[string]().
		Title("Select Expiration Time").
		Options(opts...).
		Value(bind)
}

// check the password strength
func passwordStrength(password string) error {
	pass := zxcvbn.PasswordStrength(password, nil)
	if pass.Score < 3 {
		return fmt.Errorf("password is too weak (score %d/4). Use stronger characters", pass.Score)
	}
	return nil
}

// validasi multi-email terpisah koma
func validEmails(addrs string) error {
	if strings.TrimSpace(addrs) == "" {
		return fmt.Errorf("email list cannot be empty")
	}

	emails := strings.Split(strings.ReplaceAll(addrs, " ", ""), ",")
	for _, email := range emails {
		if !govalidator.IsEmail(email) {
			return fmt.Errorf("invalid email address format: %s", email)
		}
	}
	return nil
}

func info(msg string) {
	style := lipgloss.NewStyle().
		Background(lipgloss.Color("#24a044")). // Menggunakan Hex Color yang aman
		Foreground(lipgloss.Color("#ffffff")).
		Bold(true).
		Padding(0, 1)

	title := style.Render(" INFO ")
	fmt.Printf("\n%s %s\n\n", title, msg)
}

type progressMsg struct {
	err  error
	file string
}

func send(c *resty.Client, spaceName string, token string, progressChan chan<- progressMsg, files ...string) {
	var wg sync.WaitGroup

	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()

			desc, err := os.Open(f)
			if err != nil {
				progressChan <- progressMsg{err: err, file: f}
				return
			}
			defer desc.Close()

			var uploadURL string
			var errMsg message

			res, err := c.R().
				SetAuthToken(token).
				SetBody(map[string]string{
					"space":    spaceName,
					"fileName": desc.Name(),
				}).
				SetResult(&uploadURL).
				SetResultError(&errMsg).
				Post("/up")

			if err != nil {
				progressChan <- progressMsg{err: err, file: f}
				return
			}
			if !res.IsStatusSuccess() {
				progressChan <- progressMsg{err: fmt.Errorf(errMsg.Message), file: f}
				return
			}

			// upload to s3
			res, err = c.R().SetBody(desc).Put(uploadURL)
			if err != nil {
				progressChan <- progressMsg{err: err, file: f}
				return
			}
			if !res.IsStatusSuccess() {
				progressChan <- progressMsg{err: fmt.Errorf("upload to storage failed with status %d", res.StatusCode()), file: f}
				return
			}

			progressChan <- progressMsg{err: nil, file: f}
		}(file)
	}

	wg.Wait()
	close(progressChan)
}

type bar struct {
	progress     progress.Model
	totalFiles   int
	doneFiles    int
	currentFile  string
	progressChan chan progressMsg
}

type fileDoneMsg progressMsg
type allDoneMsg struct{}

func waitForProgress(ch chan progressMsg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return allDoneMsg{}
		}
		return fileDoneMsg(msg)
	}
}

func (b bar) Init() tea.Cmd {
	return waitForProgress(b.progressChan)
}

func (b bar) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return b, tea.Quit
		}

	case fileDoneMsg:
		b.doneFiles++
		b.currentFile = msg.file

		pct := float64(b.doneFiles) / float64(b.totalFiles)
		cmd := b.progress.SetPercent(pct)

		return b, tea.Batch(cmd, waitForProgress(b.progressChan))

	case allDoneMsg:
		return b, tea.Quit

	case progress.FrameMsg:
		var cmd tea.Cmd
		b.progress, cmd = b.progress.Update(msg)
		return b, cmd
	}

	return b, nil
}

func (b bar) View() tea.View {
	s := fmt.Sprintf("\n  Uploading files... (%d/%d)\n", b.doneFiles, b.totalFiles)
	if b.currentFile != "" {
		s += fmt.Sprintf("  Current: %s\n\n", b.currentFile)
	} else {
		s += "\n"
	}

	s += "  " + b.progress.View() + "\n\n"
	s += "  Press Q or Ctrl+C to force quit.\n"
	return tea.NewView(s)
}

type picker struct {
	Space         *string
	Files         *[]string
	Err           error
	currentPath   string
	entities      []entity
	cursor        int
	selectedFiles []string
	selectedDirs  []string
}

type entity struct {
	Type       int
	Name       string
	Permission string
}

func (p *picker) Init() (cmd tea.Cmd) {
	return
}

func (p *picker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return p, tea.Quit

		case "up":
			if p.cursor > 0 {
				p.cursor--
			}

		case "down":
			if p.cursor < len(p.entities)-1 {
				p.cursor++
			}

		case "space":
			if slices.Contains(p.selectedDirs, p.currentPath) {
				return p, nil
			}

			if len(p.entities) > 0 && p.entities[p.cursor].Type == 0 {
				p.currentPath = filepath.Join(p.currentPath, p.entities[p.cursor].Name)
				p.readCurrentDir()
			}

		case "backspace":
			if p.currentPath != "." && p.currentPath != "/" {
				p.currentPath = filepath.Dir(p.currentPath)
				p.readCurrentDir()
			}

		case ".":
			if len(p.entities) == 0 {
				return p, nil
			}

			// Handle directories
			if p.entities[p.cursor].Type == 0 {
				currentDir := filepath.Join(p.currentPath, p.entities[p.cursor].Name)

				if slices.Contains(p.selectedDirs, currentDir) {
					// Remove if already selected (toggle behavior)
					index := slices.Index(p.selectedDirs, currentDir)
					if index != -1 {
						p.selectedDirs = slices.Delete(p.selectedDirs, index, index+1)
					}
				} else {
					p.selectedDirs = append(p.selectedDirs, currentDir)
				}
				return p, nil
			}

			// Handle files (Type != 0)
			currentFile := filepath.Join(p.currentPath, p.entities[p.cursor].Name)

			// We want to check if the specific file is already selected, not its parent directory.
			if slices.Contains(p.selectedFiles, currentFile) {
				index := slices.Index(p.selectedFiles, currentFile)
				if index != -1 {
					p.selectedFiles = slices.Delete(p.selectedFiles, index, index+1)
				}
			} else {
				p.selectedFiles = append(p.selectedFiles, currentFile)
			}

		case "enter":
			for _, path := range p.selectedDirs {
				_ = godirwalk.Walk(path, &godirwalk.Options{
					Callback: func(osPathname string, dir *godirwalk.Dirent) (err error) {
						if b, err := dir.IsDirOrSymlinkToDir(); b && err == nil {
							return filepath.SkipDir
						}

						p.selectedFiles = append(p.selectedFiles, osPathname)
						return nil
					},
					Unsorted: true,
				})
			}

			p.Files = &p.selectedFiles
			return p, tea.Quit
		}
	}
	return p, nil
}

func (p *picker) View() tea.View {
	text := ""

	for i, e := range p.entities {
		cursor := " "
		if p.cursor == i {
			cursor = ">"
		}

		icon := ""
		if e.Type == 0 {
			icon = "󰉋"
		}

		// FIX: Corrected format placeholder count to match the number of arguments (4 placeholders, 4 args).
		text += fmt.Sprintf("%s %s %s %s\n", cursor, e.Permission, icon, e.Name)
	}

	text += fmt.Sprintf("\nselected %d directories and %d files",
		len(p.selectedDirs), len(p.selectedFiles))

	return tea.NewView(text)
}

func (p *picker) readCurrentDir() {
	files, err := os.ReadDir(p.currentPath)
	if err != nil {
		return
	}

	p.entities = []entity{}

	for _, file := range files {
		var t int
		if file.IsDir() {
			t = 0
		} else {
			t = 1
		}

		p.entities = append(p.entities, entity{
			Name: file.Name(),
			Type: t,
		})
	}

	p.cursor = 0
}
