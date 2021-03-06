package com.community.web.service;

import com.community.web.domain.Board;
import com.community.web.repository.BoardRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
public class BoardService {
    private final BoardRepository boardRepository;

    public BoardService(BoardRepository boardRepository) {
        this.boardRepository = boardRepository;
    }

    public Page<Board> findBoardList(Pageable pageable) {
        // 사용자가 1페이지를 요청하면 실제로는 0페이지를 보여주므로 -1
        int pageNumber = pageable.getPageNumber() <= 0 ? 0 : pageable.getPageNumber() - 1;
        pageable = PageRequest.of(pageNumber, pageable.getPageSize(), new Sort(Sort.Direction.DESC, "index"));

        return boardRepository.findAll(pageable);
    }

    public Optional<Board> findBoardByIndex(long index) {
        return boardRepository.findById(index);
    }
}
