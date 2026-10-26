package tcap

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

const asn1ImportPrefix = "github.com/gomaja/go-asn1/"
const apiModulePath = "github.com/gomaja/go-asn1-tcap"

type apiReference struct {
	importPath string
	name       string
}

func (r apiReference) String() string { return r.importPath + "." + r.name }

type apiSource struct {
	file    *ast.File
	imports map[string]string
}

type apiValues struct {
	integers  map[string]bool
	constants map[string]string // upstream constant name to its INTEGER or encoding type
}

// TestPublicASN1API requires local names for exposed go-asn1 types and values.
// Only these three packages belong to the public API; local_test is not scanned.
func TestPublicASN1API(t *testing.T) {
	fset := token.NewFileSet()
	checked := importer.ForCompiler(fset, "source", nil)
	dependencies := make(map[string]apiValues)
	integerAliases, namedNumbers, encodings := 0, 0, 0
	var violations []string
	for _, dir := range []string{".", "camel", "gsmmap"} {
		sources := readAPISources(t, fset, dir)
		aliases := make(map[apiReference]string)
		wrapped := make(map[apiReference]bool)
		forwardedConstants := make(map[string]bool)
		for _, source := range sources {
			for _, decl := range source.file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.TYPE {
					continue
				}
				for _, spec := range gen.Specs {
					typ := spec.(*ast.TypeSpec)
					if typ.Name.IsExported() && typ.Assign.IsValid() {
						if ref, found := source.reference(typ.Type); found {
							aliases[ref] = typ.Name.Name
						}
					}
				}
			}
		}
		// Even when an alias exists, public declarations must use its local name.
		checkType := func(node ast.Node, source apiSource) {
			if node == nil {
				return
			}
			ast.Inspect(node, func(n ast.Node) bool {
				expr, ok := n.(ast.Expr)
				if ok {
					if ref, found := source.reference(expr); found {
						violations = append(violations, fmt.Sprintf("%s: public declaration names go-asn1 type directly: %s", fset.Position(expr.Pos()), ref))
					}
				}
				return true
			})
		}
		for _, source := range sources {
			for _, decl := range source.file.Decls {
				switch decl := decl.(type) {
				case *ast.FuncDecl:
					if decl.Name.IsExported() && (decl.Recv == nil || apiExportedReceiver(decl.Recv.List[0].Type)) {
						checkType(decl.Type, source)
					}
				case *ast.GenDecl:
					var constantValues []ast.Expr
					for _, spec := range decl.Specs {
						switch spec := spec.(type) {
						case *ast.TypeSpec:
							if !spec.Name.IsExported() {
								continue
							}
							if spec.TypeParams != nil {
								checkType(spec.TypeParams, source)
							}
							if _, direct := source.reference(spec.Type); !spec.Assign.IsValid() || !direct {
								checkType(spec.Type, source)
							}
						case *ast.ValueSpec:
							if len(spec.Values) != 0 {
								constantValues = spec.Values
							}
							for i, name := range spec.Names {
								if !name.IsExported() {
									continue
								}
								checkType(spec.Type, source)
								if decl.Tok != token.CONST {
									for _, value := range spec.Values {
										checkType(value, source)
									}
									continue
								}
								if i >= len(constantValues) {
									continue
								}
								if ref, found := source.reference(constantValues[i]); found {
									wrapped[ref] = true
									forwardedConstants[name.Name] = true
								} else {
									checkType(constantValues[i], source)
								}
							}
						}
					}
				}
			}
		}
		for ref := range aliases {
			info, loaded := dependencies[ref.importPath]
			if !loaded {
				info = readAPIValues(t, ref.importPath)
				dependencies[ref.importPath] = info
			}
			if info.integers[ref.name] {
				integerAliases++
			}
			for name, typ := range info.constants {
				if typ != ref.name {
					continue
				}
				if info.integers[typ] {
					namedNumbers++
				} else if typ == "ExternalEncoding" {
					encodings++
				}
				if !wrapped[apiReference{ref.importPath, name}] {
					violations = append(violations, fmt.Sprintf("alias %s: missing wrapper constant for %s", aliases[ref], apiReference{ref.importPath, name}))
				}
			}
		}
		importPath := apiModulePath
		if dir != "." {
			importPath += "/" + dir
		}
		pkg, err := checked.Import(importPath)
		if err != nil {
			t.Fatalf("type-check %s from source: %v", dir, err)
		}
		violations = append(violations, checkAPIReachableTypes(fset, pkg, forwardedConstants)...)
	}
	if integerAliases < 9 || namedNumbers < 34 || encodings == 0 {
		violations = append(violations, fmt.Sprintf("incomplete go-asn1 value scan: %d INTEGER aliases, %d named numbers, %d ExternalEncoding values; want at least 9, 34, 1", integerAliases, namedNumbers, encodings))
	}
	if len(violations) != 0 {
		sort.Strings(violations)
		t.Fatalf("public go-asn1 API violations (%d):\n%s", len(violations), strings.Join(violations, "\n"))
	}
}

// checkAPIReachableTypes covers inferred types and public members reached
// through private local types. An exported local alias is the naming boundary;
// go-asn1 and other dependencies are leaves, never inspected internally.
func checkAPIReachableTypes(fset *token.FileSet, pkg *types.Package, forwardedConstants map[string]bool) []string {
	var violations []string
	aliases := make(map[types.Type]*types.Alias)
	for _, name := range pkg.Scope().Names() {
		if alias, ok := pkg.Scope().Lookup(name).Type().(*types.Alias); ok && alias.Obj().Exported() {
			aliases[types.Unalias(alias)] = alias
		}
	}
	for _, name := range pkg.Scope().Names() {
		root := pkg.Scope().Lookup(name)
		if !root.Exported() {
			continue
		}
		seen := make(map[types.Type]bool)
		var walk func(types.Type, string)
		local := func(obj *types.TypeName, route string) bool {
			owner := obj.Pkg()
			if owner == nil {
				return false
			}
			if strings.HasPrefix(owner.Path(), asn1ImportPrefix) {
				violations = append(violations, fmt.Sprintf("%s: exported %s.%s: %s reaches unaliased go-asn1 type %s", fset.Position(root.Pos()), pkg.Path(), name, route, apiReference{owner.Path(), obj.Name()}))
			}
			return owner.Path() == apiModulePath || strings.HasPrefix(owner.Path(), apiModulePath+"/")
		}
		parameters := func(list *types.TypeParamList, route string) {
			for i := 0; i < list.Len(); i++ {
				param := list.At(i)
				walk(param, route+"["+param.Obj().Name()+"]")
			}
		}
		arguments := func(list *types.TypeList, route string) {
			for i := 0; i < list.Len(); i++ {
				walk(list.At(i), fmt.Sprintf("%s.arg[%d]", route, i))
			}
		}
		walk = func(typ types.Type, route string) {
			if typ == nil || seen[typ] {
				return
			}
			seen[typ] = true
			switch typ := typ.(type) {
			case *types.Alias:
				if !local(typ.Obj(), route) {
					return
				}
				parameters(typ.TypeParams(), route)
				arguments(typ.TypeArgs(), route)
				if !typ.Obj().Exported() {
					walk(typ.Rhs(), route)
				}
			case *types.Named:
				if !local(typ.Obj(), route) {
					return
				}
				parameters(typ.TypeParams(), route)
				arguments(typ.TypeArgs(), route)
				walk(typ.Underlying(), route)
				methods := make(map[string]bool)
				for _, receiver := range []types.Type{typ, types.NewPointer(typ)} {
					set := types.NewMethodSet(receiver)
					for i := 0; i < set.Len(); i++ {
						method := set.At(i)
						name := method.Obj().Name()
						if method.Obj().Exported() && !methods[name] {
							methods[name] = true
							walk(method.Type(), route+"."+name)
						}
					}
				}
			case *types.TypeParam:
				walk(typ.Constraint(), route+".constraint")
			case *types.Struct:
				for i := 0; i < typ.NumFields(); i++ {
					field := typ.Field(i)
					if field.Exported() || field.Embedded() {
						walk(field.Type(), route+"."+field.Name())
					}
				}
			case *types.Interface:
				typ.Complete()
				for i := 0; i < typ.NumMethods(); i++ {
					method := typ.Method(i)
					walk(method.Type(), route+"."+method.Name())
				}
				for i := 0; i < typ.NumEmbeddeds(); i++ {
					walk(typ.EmbeddedType(i), fmt.Sprintf("%s.embedded[%d]", route, i))
				}
			case *types.Signature:
				parameters(typ.TypeParams(), route)
				parameters(typ.RecvTypeParams(), route)
				walk(typ.Params(), route+".param")
				walk(typ.Results(), route+".result")
			case *types.Tuple:
				for i := 0; i < typ.Len(); i++ {
					walk(typ.At(i).Type(), fmt.Sprintf("%s[%d]", route, i))
				}
			case *types.Pointer:
				walk(typ.Elem(), route)
			case *types.Slice:
				walk(typ.Elem(), route+"[]")
			case *types.Array:
				walk(typ.Elem(), route+"[]")
			case *types.Map:
				walk(typ.Key(), route+".key")
				walk(typ.Elem(), route+".value")
			case *types.Chan:
				walk(typ.Elem(), route+".element")
			case *types.Union:
				for i := 0; i < typ.Len(); i++ {
					walk(typ.Term(i).Type(), fmt.Sprintf("%s.term[%d]", route, i))
				}
			}
		}
		rootType := root.Type()
		// Forwarded constants inherit the upstream named type (ViolationKind,
		// for example). The syntax pass checks their declarations and RHS;
		// use the exported alias here without blessing inferred variables.
		if forwardedConstants[name] && aliases[rootType] != nil {
			rootType = aliases[rootType]
		}
		walk(rootType, name)
	}
	return violations
}

func readAPISources(t *testing.T, fset *token.FileSet, dir string) []apiSource {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var sources []apiSource
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		imports := make(map[string]string)
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			name := path.Base(importPath)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			imports[name] = importPath
		}
		sources = append(sources, apiSource{file, imports})
	}
	if len(sources) == 0 {
		t.Fatalf("no source files in %s", dir)
	}
	return sources
}

func (source apiSource) reference(expr ast.Expr) (apiReference, bool) {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = paren.X
	}
	selector, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return apiReference{}, false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return apiReference{}, false
	}
	importPath := source.imports[qualifier.Name]
	return apiReference{importPath, selector.Sel.Name}, strings.HasPrefix(importPath, asn1ImportPrefix)
}

func apiExportedReceiver(expr ast.Expr) bool {
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.IsExported()
	case *ast.StarExpr:
		return apiExportedReceiver(expr.X)
	case *ast.IndexExpr:
		return apiExportedReceiver(expr.X)
	case *ast.IndexListExpr:
		return apiExportedReceiver(expr.X)
	default:
		return false
	}
}

// readAPIValues finds the dependency source as go-asn1-gsmmap's public API
// test does. go-asn1 gives each INTEGER type with named numbers a
// New<Type>Int64 constructor, and each named number a <Type><Name> and a
// <Type><Name>Decimal constant; ExternalEncoding's values are typed constants,
// declared with Go's implicit repetition.
func readAPIValues(t *testing.T, importPath string) apiValues {
	t.Helper()
	pkg, err := build.Default.Import(importPath, ".", build.FindOnly)
	if err != nil {
		t.Fatal(err)
	}
	sources := readAPISources(t, token.NewFileSet(), pkg.Dir)
	info := apiValues{make(map[string]bool), make(map[string]string)}
	constants := make(map[string]bool)
	types := make(map[string]bool)
	functions := make(map[string]bool)
	for _, source := range sources {
		for _, decl := range source.file.Decls {
			if function, ok := decl.(*ast.FuncDecl); ok {
				if function.Recv == nil {
					functions[function.Name.Name] = true
				}
				continue
			}
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			var constantType string
			for _, spec := range gen.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					types[spec.Name.Name] = true
				case *ast.ValueSpec:
					if gen.Tok != token.CONST {
						continue
					}
					if len(spec.Values) != 0 {
						constantType = ""
						if typ, ok := spec.Type.(*ast.Ident); ok {
							constantType = typ.Name
						}
					}
					for _, name := range spec.Names {
						constants[name.Name] = true
						if constantType == "ExternalEncoding" {
							info.constants[name.Name] = constantType
						}
					}
				}
			}
		}
	}
	for typ := range types {
		if functions["New"+typ+"Int64"] {
			info.integers[typ] = true
		}
	}
	for typ := range info.integers {
		for name := range constants {
			if strings.HasPrefix(name, typ) && constants[name+"Decimal"] {
				info.constants[name] = typ
			}
		}
	}
	return info
}
