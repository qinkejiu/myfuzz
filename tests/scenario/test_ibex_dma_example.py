from myfuzz.scenario.ibex_dma_example import ibex_dma_images,MAIN,ISR,SOURCE,WORDS


def test_cpu_program_materializes_source_and_configures_actual_start_word():
    images=ibex_dma_images()
    assert SOURCE not in images
    main=[int.from_bytes(images[MAIN][i:i+4],'little') for i in range(0,len(images[MAIN]),4)]
    assert 0x0fed01b7 in main  # LUI x3,0xfed0 followed by ADDI 4
    assert len([w for w in main if w&0x7f==0x23]) == 8
    assert len(images[MAIN])+MAIN < ISR
    assert len(WORDS)==4 and len(set(WORDS))==4
    assert images[MAIN] != ibex_dma_images(start_key=0x3db)[MAIN]
