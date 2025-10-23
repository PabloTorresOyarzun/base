#!/bin/sh

# Esperar a que Kong esté listo
echo "Esperando a que Kong esté disponible..."
until curl -s http://kong:8001/status > /dev/null 2>&1; do
    echo "Kong no está listo, esperando..."
    sleep 3
done

echo "Kong está listo. Configurando rutas..."

# Crear servicio para el portal
curl -i -X POST http://kong:8001/services \
  --data name=portal-service \
  --data url=http://portal:8100

# Crear ruta para el portal (strip_path=false: Kong envía ruta completa /portal/... al backend)
curl -i -X POST http://kong:8001/services/portal-service/routes \
  --data "paths[]=/portal" \
  --data "strip_path=true" \
  --data name=portal-route

echo "Configuración de Kong completada."
echo "Portal accesible en: http://localhost:8000/portal"