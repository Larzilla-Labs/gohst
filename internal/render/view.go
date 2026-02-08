package render

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gohst/internal/auth"
	"gohst/internal/config"
	"gohst/internal/session"
	"gohst/internal/utils"
)

type TemplateData struct {
    CSRF    		*CSRF      			// CSRF token for form protection
    Auth	  		any      			// Pointer to the authenticated user (if any)
    Flash 	        map[string]any 		// Slice for any flash messages (success/error)
	OldData    	    map[string]any 		// Map for old input values (for form repopulation)
    Data         	any  				// Additional dynamic data specific to each page
	Request         *RequestProps       // Request metadata (path, method, etc.)
}

type RequestProps struct {
	Path   string // Request URI path
	Method string // HTTP method (GET, POST, etc.)
	URL    string // Full URL
}

type ViewData struct {
	CSRF	 *CSRF
	Auth	 any      // Pointer to the authenticated user (if any)
    Props    any
    Content  template.HTML
	Title   string         // Page title set via SetTitle
}

type View struct {
	Template 	*template.Template
	Layout  	string
	Dirs    ViewDirs
	title   string         // holds per-request page title
}

type ViewDirs struct {
	Layouts 	string
	Templates 	string
	Views 		string
	Partials 	string
	Components 	string
}


const defaultLayout string = "layouts/default"

const errorTemplate string = `<!DOCTYPE html>
<html>
<head>
    <title>%s</title>
    <style>
        body { background-color: #1a1a1a; color: #e0e0e0; font-family: system-ui, -apple-system, sans-serif; padding: 2rem; }
        .container { max-width: 800px; margin: 0 auto; }
        .error-card { background-color: #2d2d2d; border: 1px solid #404040; border-radius: 8px; padding: 1.5rem; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        h1 { color: #ff6b6b; margin-top: 0; font-size: 1.5rem; border-bottom: 1px solid #404040; padding-bottom: 1rem; }
        pre { background-color: #1a1a1a; padding: 1rem; border-radius: 4px; overflow-x: auto; color: #ffb86c; font-family: monospace; font-size: 0.9rem; border: 1px solid #404040; }
        .footer { margin-top: 1rem; color: #888; font-size: 0.8rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="error-card">
            <h1>👻 %s</h1>
            <pre>%s</pre>
            <div class="footer">
                Gohst Framework • Development Mode
            </div>
        </div>
    </div>
</body>
</html>`

func NewView() *View {
	templateFuncs := TemplateFuncs()
	view := &View{
		Template: template.New("").Funcs(templateFuncs),
		Layout: defaultLayout,
		Dirs: ViewDirs{
			Layouts: "layouts",
			Templates: "templates",
			Views: "views",
			Partials: "partials",
			Components: "components",
		},
	}

	view.Init()

	return view
}

func (v *View) Init() {
	v.loadAll()
}

func (v *View) LoadTemplates() {
	// Go’s ParseGlob does not support brace expansion.
	// Load HTML and tmpl files separately if needed.
	_, err := v.Template.ParseGlob("templates/**/*.html")
	if err != nil {
		log.Fatalf("Error parsing HTML templates: %v", err)
	}
	_, err = v.Template.ParseGlob("templates/**/*.tmpl")
	if err != nil {
		log.Fatalf("Error parsing Tmpl templates: %v", err)
	}
}

// loadAll loads all templates from the specified directory and parses them into the template engine.
func (v *View) loadAll() {
	dirPath := v.Dirs.Templates
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			name, err := filepath.Rel(dirPath, path)
			if err != nil {
				log.Fatal("No rel base path found.", err)
			}

			// Standardize path and remove extension
			name = filepath.ToSlash(name)
			name = name[:len(name)-len(filepath.Ext(name))]

			// Parse into base template
			_, err = v.Template.New(name).Parse(string(content))
			if err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		log.Fatalf("Error loading tempaltes: %v", err)
	}
}

// Render renders a view with the given name and data. Render the content then the whole view with the layout.
func (v *View) Render(w http.ResponseWriter, r *http.Request, viewName string, data ...interface{}) error {
	var viewContent bytes.Buffer
	useData := utils.StructSafe(data)
    sess := session.FromContext(r.Context())
	csrf := GetCSRF(r)

	var authData any
	var flash map[string]any
	var oldData map[string]any

	if sess != nil {
		authData = auth.GetAuthData(sess)
		flash = sess.GetAllFlash()
		oldData = sess.GetAllOld()
	}

	// Define template data for globlal use in templates
	templateData := TemplateData{
		CSRF: csrf,
		Auth: authData,
		Data: useData,
		Flash: flash,
        OldData:   oldData,
		Request: &RequestProps{
			Path:   r.URL.Path,
			Method: r.Method,
			URL:    r.URL.String(),
		},
	}

	useViewName := v.Dirs.Views + "/" + viewName
	err := v.Template.ExecuteTemplate(&viewContent, useViewName, templateData)
	if err != nil {
		return v.handleError(w, err)
	}

   // Capture and clear the title so it doesn't persist across requests
   title := v.title
   v.title = ""
	td := ViewData{
		CSRF: csrf,
		Auth: authData,
	   Title:   title,
        Props:   struct{}{}, // Possibly to load other view data
        Content: template.HTML(viewContent.String()),
    }

	// Buffer the final output too, to catch layout errors
	var finalOutput bytes.Buffer
	err = v.Template.ExecuteTemplate(&finalOutput, v.Layout, td)
	if err != nil {
		return v.handleError(w, err)
	}

	_, err = finalOutput.WriteTo(w)
	return err
}

// RenderError renders the error template directly to the response writer.
// This is useful for middleware or other parts of the framework that need to show an error page.
func RenderError(w http.ResponseWriter, title string, err interface{}) {
	if config.GetAppConfig().IsDevelopment() {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, errorTemplate, title, title, err)
	} else {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (v *View) handleError(w http.ResponseWriter, err error) error {
	log.Println("Error executing template:", err)
	RenderError(w, "Template Rendering Error", err)
	return nil // Error handled
}

// SetTitle sets the page title for the next render.
func (v *View) SetTitle(title string) {
	v.title = title
}

// GetTitle gets the page title for the current request.
func (v *View) GetTitle() string {
	return v.title
}

// Set the layout to be used for rendering
func (v *View) SetLayout(layout string) {
	if layout != "" {
		v.Layout = layout
	} else {
		v.Layout = defaultLayout
	}
}

// Get the lauout to be used for rendering
func (v *View) GetLayout() string {
	if v.Layout == "" {
		return defaultLayout
	}
	return v.Layout
}

