# Guía de Releases y Auto-Actualización

## Requisitos previos

- Go 1.25+ instalado
- Acceso push al repositorio `KAPA-8/grd-siem-agent`
- GitHub CLI (`gh`) instalado (opcional, para crear releases manuales)

---

## Crear una nueva versión

### 1. Preparar los cambios

```bash
# Asegúrate de estar en main y actualizado
git checkout main
git pull origin main

# Verifica que todo compile y pase tests
make test
make build
```

### 2. Crear el tag con versionado semántico

Usa el formato `vMAJOR.MINOR.PATCH`:

| Tipo de cambio | Ejemplo | Cuándo usarlo |
|----------------|---------|---------------|
| **PATCH** `v1.0.1` | Fix de bug, corrección menor | No rompe nada, solo corrige |
| **MINOR** `v1.1.0` | Nueva funcionalidad | Agrega algo nuevo, compatible hacia atrás |
| **MAJOR** `v2.0.0` | Cambio breaking | Cambia config, API, o comportamiento existente |

```bash
# Ver la última versión publicada
git tag --sort=-v:refname | head -5

# Crear el tag (ejemplo: v0.2.0)
git tag v0.2.0

# Push del tag a GitHub
git push origin v0.2.0
```

### 3. GitHub Actions hace el resto

Al hacer push del tag `v*`, el workflow `.github/workflows/release.yml` automáticamente:

1. Ejecuta los tests
2. Compila binarios para 5 plataformas:
   - `grd-siem-agent-linux-amd64`
   - `grd-siem-agent-linux-arm64`
   - `grd-siem-agent-darwin-amd64`
   - `grd-siem-agent-darwin-arm64`
   - `grd-siem-agent-windows-amd64.exe`
3. Genera `checksums.txt` con SHA256
4. Crea un GitHub Release con todos los assets

### 4. Verificar el release

```bash
# Ver el estado del workflow
gh run list --workflow=release.yml

# Ver los releases publicados
gh release list

# Ver los assets de un release específico
gh release view v0.2.0
```

También puedes verificar en: `https://github.com/KAPA-8/grd-siem-agent/releases`

---

## Qué pasa en los agentes desplegados

Una vez publicado el release, los agentes se actualizan automáticamente:

```
Tag push → GitHub Actions → Release publicado
                                    ↓
                        Agente detecta nueva versión
                          (chequeo cada 6 horas)
                                    ↓
                        Descarga binario + checksums
                                    ↓
                        Verifica SHA256
                                    ↓
                        Stage en /var/lib/grd-siem-agent/.update/
                                    ↓
                        Agente sale con código 2
                                    ↓
                        systemd reinicia el servicio
                                    ↓
                        ExecStartPre ejecuta apply-update.sh
                          → Verifica checksum
                          → Smoke test (version)
                          → Reemplaza binario
                                    ↓
                        Agente arranca con nueva versión
```

**Tiempo estimado**: Los agentes detectarán la actualización en un máximo de 6 horas (configurable en `update.check_interval_hours`).

---

## Forzar actualización inmediata

Si no quieres esperar al chequeo periódico:

```bash
# En el servidor donde corre el agente:

# Solo verificar si hay actualización disponible
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent update --check \
  --config /etc/grd-siem-agent/config.yaml

# Descargar y stagear la actualización
sudo -u grd-agent /opt/grd-siem-agent/grd-siem-agent update \
  --config /etc/grd-siem-agent/config.yaml

# Reiniciar para aplicar
sudo systemctl restart grd-siem-agent

# Verificar la nueva versión
sudo journalctl -u grd-siem-agent -n 20 --no-pager
```

---

## Release con notas personalizadas

Si quieres agregar notas al release en lugar de las auto-generadas:

```bash
# Crear tag con mensaje
git tag -a v0.3.0 -m "Soporte para Splunk collector"
git push origin v0.3.0
```

O editar las notas después de que Actions cree el release:

```bash
gh release edit v0.3.0 --notes "## Cambios

- Agregado collector para Splunk
- Fix: reconexión automática a QRadar tras timeout
- Mejora: reducción de uso de memoria en buffer SQLite"
```

---

## Rollback de versión

Si una versión tiene problemas y necesitas revertir:

```bash
# Opción 1: Publicar un nuevo patch con el fix
git revert <commit-problemático>
git tag v0.2.1
git push origin v0.2.1

# Opción 2: Reinstalar manualmente el binario anterior
# Descargar el binario de la versión anterior
gh release download v0.1.0 -p "grd-siem-agent-linux-amd64" -D /tmp

# Reemplazar y reiniciar
sudo cp /tmp/grd-siem-agent-linux-amd64 /opt/grd-siem-agent/grd-siem-agent
sudo chmod 755 /opt/grd-siem-agent/grd-siem-agent
sudo systemctl restart grd-siem-agent
```

---

## Configuración de auto-update en los agentes

En `/etc/grd-siem-agent/config.yaml`:

```yaml
update:
  enabled: true                                    # false para desactivar
  check_interval_hours: 6                          # frecuencia de chequeo
  github_repo: "KAPA-8/grd-siem-agent"      # owner/repo en GitHub
  allow_prerelease: false                          # true para recibir betas
```

Para desactivar auto-update en un agente específico:

```yaml
update:
  enabled: false
```

---

## Checklist rápido para cada release

```
[ ] Cambios commiteados y pusheados a main
[ ] Tests pasan: make test
[ ] Compila correctamente: make build
[ ] Tag creado: git tag vX.Y.Z
[ ] Tag pusheado: git push origin vX.Y.Z
[ ] Workflow completado: gh run list --workflow=release.yml
[ ] Release visible con assets: gh release view vX.Y.Z
```

---

## Estructura de un release en GitHub

```
Release v0.2.0
├── grd-siem-agent-linux-amd64        (binario Linux x86_64)
├── grd-siem-agent-linux-arm64        (binario Linux ARM64)
├── grd-siem-agent-darwin-amd64       (binario macOS Intel)
├── grd-siem-agent-darwin-arm64       (binario macOS Apple Silicon)
├── grd-siem-agent-windows-amd64.exe  (binario Windows x86_64)
└── checksums.txt                     (SHA256 de cada binario)
```
