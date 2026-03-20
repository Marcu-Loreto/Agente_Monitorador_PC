@echo off
:: ============================================================
:: Auto-elevação para Administrador
:: ============================================================
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Solicitando privilegios de administrador...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: ============================================================
:: Já está como Admin - iniciar o Streamlit
:: ============================================================
title Monitor PC - Modo Administrador
cd /d "d:\Projetos_IA\Loreto\agente_PC\Agente_Monitorador_PC"

:: Caminho completo do Python do usuário marcu
set "PYTHON=C:\Users\marcu\AppData\Local\Programs\Python\Python313\python.exe"

:: Garantir que user site-packages seja encontrado
set "PYTHONPATH=C:\Users\marcu\AppData\Roaming\Python\Python313\site-packages;%PYTHONPATH%"

echo.
echo ========================================
echo   Monitor PC - Rodando como ADMIN
echo ========================================
echo.
"%PYTHON%" -m streamlit run monitor.py
pause
