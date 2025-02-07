#!/bin/sh
ENGINE_DIR=$1  #PATH to engine
JS_FILE=$2    #PATH to js_file

FOLDER_NAME=$(basename $ENGINE_DIR)
if [[ "$FOLDER_NAME" == "ChakraCore" ]]; then
  EXEC_PATH="out/Release/ch"
  LCOV_PATH="out/Release/bin/ch/CMakeFiles/ch.dir/"
elif [[ "$FOLDER_NAME" == "WebKit" ]]; then
  EXEC_PATH="CovBuild/bin/jsc"
  LCOV_PATH="CovBuild/"
else
  echo "Not correct folder."
fi

find /home/notebooks/erokhina/code_generator/ -name 'llvm-gcov.sh' -exec cp -t $LOCATION {} +
echo "Запуск seed'a"
echo ${ENGINE_DIR}${EXEC_PATH} ${JS_FILE}
${ENGINE_DIR}${EXEC_PATH} ${JS_FILE}

echo "Формирование покрытия"
lcov --directory ${ENGINE_DIR}${LCOV_PATH} --gcov-tool /home/jovyan/js_generator/llvm-gcov.sh --capture -o ${ENGINE_DIR}${LCOV_PATH}cov.info

find ${ENGINE_DIR}bin/ch/CMakeFiles/ch.dir/ -name '*.c' -exec cp -t ${LOCATION} {} +
find ${ENGINE_DIR}bin/ch/CMakeFiles/ch.dir/ -name '*.gcno' -exec cp -t ${LOCATION} {} +
find ${ENGINE_DIR}bin/ch/CMakeFiles/ch.dir/ -name '*.gcda' -exec mv -t ${LOCATION} {} +

echo "Конвертация файла покрытия"
fastcov -C ${LOCATION}cov.info -o ${LOCATION}cov_${JS_NAME}.json

echo "Генерация html-файла"
genhtml ${ENGINE_DIR}${LCOV_PATH}cov.info -o ${ENGINE_DIR}${LCOV_PATH}output
