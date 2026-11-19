if(NOT DEFINED SOFTSDFINIT)
	message(FATAL_ERROR "SOFTSDFINIT is not set")
endif()
if(NOT DEFINED WORK_DIR)
	message(FATAL_ERROR "WORK_DIR is not set")
endif()

file(REMOVE_RECURSE "${WORK_DIR}")
file(MAKE_DIRECTORY "${WORK_DIR}")

set(test_pass "P@ssw0rd")

# key indexes 1 and 2: IPK/ISK and KEK round trips need two of each
foreach(idx RANGE 1 2)
	execute_process(
		COMMAND "${SOFTSDFINIT}" -kek ${idx} -key ${idx} -pass "${test_pass}"
		WORKING_DIRECTORY "${WORK_DIR}"
		RESULT_VARIABLE init_result)
	if(NOT init_result EQUAL 0)
		message(FATAL_ERROR "softsdfinit -kek ${idx} -key ${idx} failed with exit code ${init_result}")
	endif()
endforeach()
