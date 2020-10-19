/*
 * imgzip.c
 *
 *  Created on: 2013-02-22
 *      Author: lizhitao
 */
#include "imgzip.h"
#include <string.h>
static MagickWand *KUCHE_WATER, *TAOFANG_WATER, *HOST_WATER;
static char *KUCHE_404, *TAOFANG_404, *HOST_404;
static int KUCHE_404_LEN, TAOFANG_404_LEN, HOST_404_LEN;
static int read_file(char *fileName, char **base);
static int imgZoomHandler(MagickWand *magickWand, int width, int height) {
	int isGif = 0;
	char *fmt = MagickGetImageFormat(magickWand);
	if (strcmp(fmt, "GIF") == 0) {
		isGif = 1;
	}
	free(fmt);
	if (MagickResizeImage(magickWand, width, height, UndefinedFilter, 1) == 0) {
		return IMGZIP_ERR;
	}
	if (isGif) {
		while (MagickNextImage(magickWand)) {
			if (MagickResizeImage(magickWand, width, height, UndefinedFilter, 1) == 0) {
				return IMGZIP_ERR;
			}
		}
		MagickResetIterator(magickWand);
	}
	return IMGZIP_OK;
}
int imgZoomInit(ngx_str_t *resouresPath) {
	InitializeMagick(NULL);
	KUCHE_WATER = NewMagickWand();
	TAOFANG_WATER = NewMagickWand();
	HOST_WATER = NewMagickWand();
	KUCHE_404 = malloc(1);
	TAOFANG_404 = malloc(1);
	HOST_404 = malloc(1);
	if (resouresPath) {
		size_t len = resouresPath->len;
		char *f = malloc(len + 40);
		strncpy(f, (char*) resouresPath->data, len);
		if (f[len - 1] != '/') {
			f[len] = '/';
			++len;
		}
		strcpy(f + len, "kuche_water.png");

		int i = MagickReadImage(KUCHE_WATER, f);
		if (i == 0)
			return IMGZIP_ERR;
		strcpy(f + len, "58_water.png");
		i = MagickReadImage(TAOFANG_WATER, f);
		if (i == 0)
			return IMGZIP_ERR;
		strcpy(f + len, "58_water.png");
		i = MagickReadImage(HOST_WATER, f);
		if (i == 0)
			return IMGZIP_ERR;
		strcpy(f + len, "kuche-404.png");
		KUCHE_404_LEN = read_file(f, &KUCHE_404);
		if (KUCHE_404_LEN == -1)
			return IMGZIP_ERR;
		strcpy(f + len, "taofang-404.png");
		TAOFANG_404_LEN = read_file(f, &TAOFANG_404);
		if (TAOFANG_404_LEN == -1)
			return IMGZIP_ERR;
		strcpy(f + len, "404.png");
		HOST_404_LEN = read_file(f, &HOST_404);
		if (HOST_404_LEN == -1)
			return IMGZIP_ERR;
	} else {
		int i = MagickReadImage(KUCHE_WATER, "./resources/kuche_water.png");
		if (i == 0)
			return IMGZIP_ERR;
		i = MagickReadImage(TAOFANG_WATER, "./resources/58_water.png");
		if (i == 0)
			return IMGZIP_ERR;
		i = MagickReadImage(HOST_WATER, "./resources/58_water.png");
		if (i == 0)
			return IMGZIP_ERR;
		KUCHE_404_LEN = read_file("./resources/kuche-404.png", &KUCHE_404);
		if (KUCHE_404_LEN == -1)
			return IMGZIP_ERR;
		TAOFANG_404_LEN = read_file("./resources/taofang-404.png", &TAOFANG_404);
		if (TAOFANG_404_LEN == -1)
			return IMGZIP_ERR;
		HOST_404_LEN = read_file("./resources/404.png", &HOST_404);
		if (HOST_404_LEN == -1)
			return IMGZIP_ERR;
	}

	return IMGZIP_OK;
}
int imgCut(MagickWand *magickWand, int x, int y, int width, int height) {
	int isGif = 0;
	char *fmt = MagickGetImageFormat(magickWand);
	if (strcmp(fmt, "GIF") == 0) {
			isGif = 1;
			return IMGZIP_OK;  //如果图片为gif格式，则不进行剪切
	}
	free(fmt);
	if (MagickCropImage(magickWand, width, height, x, y) == 0) {
		return IMGZIP_ERR;
	}
	if (isGif) {
		while (MagickNextImage(magickWand)) {
			if (MagickCropImage(magickWand, width, height, x, y) == 0) {
				return IMGZIP_ERR;
			}
		}
		MagickResetIterator(magickWand);
	}
	return IMGZIP_OK;
}
int imgZoom(MagickWand *magickWand, int tw, int th, ImgZoomType zoomType) {
	int targetWidth = tw;
	int targetHeight = th;
	if (targetWidth == 0 && targetHeight == 0) {
		return IMGZIP_OK;
	}
	if (targetHeight > IMG_MAX_HEIGHT) {
		targetHeight = IMG_MAX_HEIGHT;
	}
	if (targetWidth > IMG_MAX_WIDTH) {
		targetWidth = IMG_MAX_WIDTH;
	}
	int width = MagickGetImageWidth(magickWand);
	int height = MagickGetImageHeight(magickWand);
	if (targetWidth == 0) {
			targetWidth = targetHeight * width / height;
	} else if (targetHeight == 0) {
			targetHeight = targetWidth * height / width;
	} else {
			switch (zoomType) {
			case ZOOM_By_WIDTH:
				targetHeight = targetWidth * height / width;
				break;
			case ZOOM_BY_HEIGHT:
				targetWidth = targetHeight * width / height;
				break;
			case ZOOM_BY_BIG:
			case ZOOM_BY_BOTH:
				if (width / (float) targetWidth > height / (float) targetHeight) {
					targetHeight = targetWidth * height / width;
				} else {
					targetWidth = targetHeight * width / height;
				}
				break;
			case ZOOM_BY_SMALL_TOP:
			case ZOOM_BY_SMALL_MIDDLE:
			case ZOOM_BY_SMALL_BOTTOM:
				if (width / (float) targetWidth > height / (float) targetHeight) {
					targetWidth = targetHeight * width / height;
				} else {
					targetHeight = targetWidth * height / width;
				}
				break;
			default:
				if (width / (float) targetWidth > height / (float) targetHeight) {
					targetWidth = targetHeight * width / height;
				} else {
					targetHeight = targetWidth * height / width;
				}
				break;
			}
	}
	if (targetWidth > width && targetHeight > height) {
		return IMGZIP_OK;
	}
	if (imgZoomHandler(magickWand, targetWidth, targetHeight) != IMGZIP_OK) {
		return IMGZIP_ERR;
	}
	if ((targetHeight > th || targetWidth > tw) && tw > 0 && th > 0) {
		if (zoomType == ZOOM_BY_SMALL_BOTTOM) {
				targetWidth = targetWidth - tw;
				targetHeight = targetHeight - th;
				return imgCut(magickWand, targetWidth > 0 ? targetWidth : 0, targetHeight > 0 ? targetHeight : 0, tw, th);
		} else if (zoomType == ZOOM_BY_SMALL_TOP) {
				return imgCut(magickWand, 0, 0, tw, th);
		} else if (zoomType == ZOOM_BY_SMALL_MIDDLE) {
				targetWidth = (targetWidth - tw) / 2;
				targetHeight = (targetHeight - th) / 2;
				return imgCut(magickWand, targetWidth > 0 ? targetWidth : 0, targetHeight > 0 ? targetHeight : 0, tw, th);
		}
	}
	return IMGZIP_OK;
}
int imgAddWater(MagickWand *magickWand, WaterType waterType) {
	int width = MagickGetImageWidth(magickWand);
	int height = MagickGetImageHeight(magickWand);
	if (width < ADD_WATER_MIN_SIZE || height < ADD_WATER_MIN_SIZE) {
		return IMGZIP_OK;
	}
	MagickWand *waterWand;
	if (waterType == WATER_TYPE_KUCHE) {
		waterWand = KUCHE_WATER;
	} else if (waterType == WATER_TYPE_TAOFANG) {
		waterWand = TAOFANG_WATER;
	} else {
		waterWand = HOST_WATER;
	}
	int waterWidth = MagickGetImageWidth(waterWand);
	int waterHeight = MagickGetImageHeight(waterWand);
	int flg = 0;
	if (width / waterWidth < 3 || height / waterHeight < 3) {
		flg = 1;
		waterWand = CloneMagickWand(waterWand);
		imgZoom(waterWand, width / 3, 0, ZOOM_By_WIDTH);
	}
	long x = (width - MagickGetImageWidth(waterWand)) * ADD_WATER_POINT_X;
	long y = (height - MagickGetImageHeight(waterWand)) * ADD_WATER_POINT_Y;
	int i = MagickCompositeImage(magickWand, waterWand, OverCompositeOp, x, y);
	if (flg == 1) {
		DestroyMagickWand(waterWand);
	}
	return i;
}

char *getNotFoundImage(int siteId, int *len) {
	switch (siteId) {
	case 1:
		*len = KUCHE_404_LEN;
		return KUCHE_404;
		break;
	case 2:
		*len = TAOFANG_404_LEN;
		return TAOFANG_404;
	default:
		*len = HOST_404_LEN;
		return HOST_404;
		break;
	}
	return NULL;
}
static int read_file(char *fileName, char **base) {
	FILE *fp = fopen(fileName, "r");
	if (fp == NULL) {
		printf("Can't open file: %s.", fileName);
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	int file_size = ftell(fp);
	*base = realloc(*base, file_size);
	if (*base == NULL) {
		printf("The file %s is too big", fileName);
		fclose(fp);
		exit(0);
	}
	fseek(fp, 0, SEEK_SET);
	file_size = fread(*base, 1, file_size, fp);
	fclose(fp);
	return file_size;
}
