"""
Модуль для сбора и вывода метрик в консоль.
"""
import time
import logging

logger = logging.getLogger(__name__)

# Глобальные счётчики для текущего запуска
_stats = {
    'files_scanned': 0,
    'violations': 0,
    'duration': 0.0,
    'type': 'file'  # 'file' или 'code'
}


def reset_metrics(scan_type='file'):
    """Сбрасывает метрики перед новым сканированием."""
    _stats['files_scanned'] = 0
    _stats['violations'] = 0
    _stats['duration'] = 0.0
    _stats['type'] = scan_type


def inc_files_scanned():
    """Увеличивает счётчик просканированных файлов на 1."""
    _stats['files_scanned'] += 1


def inc_violations():
    """Увеличивает счётчик нарушений на 1."""
    _stats['violations'] += 1


def set_duration(seconds):
    """Устанавливает длительность сканирования."""
    _stats['duration'] = seconds


def print_metrics():
    """Выводит собранные метрики в консоль."""
    logger.info("=" * 50)
    logger.info("📊 СТАТИСТИКА СКАНИРОВАНИЯ (%s)", _stats['type'].upper())
    logger.info("  📁 Просканировано файлов: %d", _stats['files_scanned'])
    logger.info("  ⚠️  Нарушений найдено: %d", _stats['violations'])
    logger.info("  ⏱️  Время сканирования: %.3f сек", _stats['duration'])
    logger.info("=" * 50)